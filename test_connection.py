"""Quick Supabase connection diagnostic — run with: python test_connection.py"""
import asyncio
import ssl
import asyncpg

CONFIGS = [
    {
        "label": "Session Pooler (port 5432)",
        "host": "aws-1-us-east-1.pooler.supabase.com",
        "port": 5432,
        "user": "postgres.ejsjqhqjjgpqsmhtyers",
        "password": "Retread-Captive5-Recall-Patronize-Escapable",
        "database": "postgres",
    },
    {
        "label": "Session Pooler (port 6543)",
        "host": "aws-1-us-east-1.pooler.supabase.com",
        "port": 6543,
        "user": "postgres.ejsjqhqjjgpqsmhtyers",
        "password": "Retread-Captive5-Recall-Patronize-Escapable",
        "database": "postgres",
    },
    {
        "label": "Direct Connection (port 5432)",
        "host": "db.ejsjqhqjjgpqsmhtyers.supabase.co",
        "port": 5432,
        "user": "postgres",
        "password": "Retread-Captive5-Recall-Patronize-Escapable",
        "database": "postgres",
    },
]


async def try_connect(cfg):
    label = cfg.pop("label")
    print(f"\n--- Testing: {label} ---")
    print(f"    Host: {cfg['host']}:{cfg['port']}")
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(**cfg, ssl="require"),
            timeout=10,
        )
        version = await conn.fetchval("SELECT version()")
        print(f"    ✅ SUCCESS! PostgreSQL: {version[:60]}...")
        await conn.close()
        return label
    except asyncio.TimeoutError:
        print(f"    ❌ TIMEOUT (10s) — host reachable but connection hung")
    except ConnectionRefusedError:
        print(f"    ❌ Connection refused — port not open or blocked")
    except OSError as e:
        print(f"    ❌ OS error: {e}")
    except Exception as e:
        print(f"    ❌ Error: {type(e).__name__}: {e}")
    return None


async def main():
    print("Supabase Connection Diagnostic")
    print("=" * 50)
    winner = None
    for cfg in CONFIGS:
        result = await try_connect(dict(cfg))
        if result and not winner:
            winner = result
    print("\n" + "=" * 50)
    if winner:
        print(f"✅ Working config: {winner}")
    else:
        print("❌ No configuration worked. Check:")
        print("   1. Is your Supabase project active (not paused)?")
        print("   2. Are you on a network that blocks outbound PostgreSQL (port 5432/6543)?")
        print("   3. Try from a different network (some corporate/school networks block DB ports)")


asyncio.run(main())
