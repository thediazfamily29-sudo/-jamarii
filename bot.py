
import os
import sqlite3
import secrets
import string
import hashlib
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DB_FILE = "jamari.db"

def connect_db():
    db = sqlite3.connect(DB_FILE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT DEFAULT 'LIFETIME',
            revoked INTEGER DEFAULT 0,
            created_by TEXT NOT NULL
        )
    """)
    return db

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def make_key():
    alphabet = string.ascii_uppercase + string.digits
    return "JAMARI-" + "-".join(
        "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(3)
    )

class JamariBot(commands.Bot):
    async def setup_hook(self):
        await self.tree.sync()

intents = discord.Intents.default()
bot = JamariBot(command_prefix="!", intents=intents)

def is_admin(interaction: discord.Interaction):
    return interaction.user.guild_permissions.administrator

@bot.event
async def on_ready():
    connect_db().close()
    print(f"JAMARI bot online: {bot.user}")

@bot.tree.command(name="key_generate", description="Generate an application access key")
@app_commands.describe(username="Account username for this key")
async def key_generate(interaction: discord.Interaction, username: str):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "Administrator permission required.", ephemeral=True
        )
        return

    key = make_key()
    with connect_db() as db:
        db.execute(
            "INSERT INTO keys (key_hash, username, created_by) VALUES (?, ?, ?)",
            (hash_key(key), username, str(interaction.user.id))
        )

    await interaction.response.send_message(
        f"**JAMARI key created**\nUsername: `{username}`\n"
        f"Key: `{key}`\nExpiration: Lifetime\n"
        "Save this key privately; it is stored as a hash.",
        ephemeral=True
    )

@bot.tree.command(name="key_list", description="List registered key usernames")
async def key_list(interaction: discord.Interaction):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "Administrator permission required.", ephemeral=True
        )
        return

    with connect_db() as db:
        rows = db.execute(
            "SELECT username, revoked, expires_at FROM keys ORDER BY username"
        ).fetchall()

    if not rows:
        result = "No keys registered."
    else:
        result = "\n".join(
            f"User: `{u}` | {'Revoked' if r else 'Active'} | {e}"
            for u, r, e in rows[:40]
        )

    await interaction.response.send_message(result, ephemeral=True)

@bot.tree.command(name="key_revoke", description="Revoke an access key")
@app_commands.describe(key="Full JAMARI key to revoke")
async def key_revoke(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "Administrator permission required.", ephemeral=True
        )
        return

    with connect_db() as db:
        cur = db.execute(
            "UPDATE keys SET revoked=1 WHERE key_hash=?", (hash_key(key),)
        )

    await interaction.response.send_message(
        "Key revoked." if cur.rowcount else "Key not found.",
        ephemeral=True
    )

@bot.tree.command(name="key_reactivate", description="Reactivate a revoked key")
@app_commands.describe(key="Full JAMARI key to reactivate")
async def key_reactivate(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "Administrator permission required.", ephemeral=True
        )
        return

    with connect_db() as db:
        cur = db.execute(
            "UPDATE keys SET revoked=0 WHERE key_hash=?", (hash_key(key),)
        )

    await interaction.response.send_message(
        "Key reactivated." if cur.rowcount else "Key not found.",
        ephemeral=True
    )

if not TOKEN:
    raise SystemExit(
        "Missing DISCORD_BOT_TOKEN. Create a .env file with your bot token."
    )

bot.run(TOKEN)
