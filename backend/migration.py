# fix_migration.py - Run this to complete the migration
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://area51_system:87587@localhost:5432/area51_db"

async def fix_migration():
    engine = create_async_engine(DATABASE_URL)
    
    # Run each index creation separately
    index_queries = [
        "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);",
        "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);", 
        "CREATE INDEX IF NOT EXISTS idx_devices_environment ON devices(environment);",
        "CREATE INDEX IF NOT EXISTS idx_devices_device_type ON devices(device_type);",
        "CREATE INDEX IF NOT EXISTS idx_devices_name ON devices(name);"
    ]
    
    # Update existing devices with default values
    update_queries = [
        """
        UPDATE devices SET 
            status = 'online',
            cpu_usage = RANDOM() * 30 + 10,
            memory_usage = RANDOM() * 40 + 20,
            disk_usage = RANDOM() * 35 + 15,
            uptime = FLOOR(RANDOM() * 86400 + 3600),
            last_seen = NOW(),
            updated_at = NOW()
        WHERE status IS NULL OR status = '';
        """,
        """
        UPDATE users SET 
            role = 'admin',
            last_login = NOW()
        WHERE role IS NULL;
        """
    ]
    
    async with engine.begin() as conn:
        # Create indexes
        for query in index_queries:
            try:
                await conn.execute(text(query))
                print(f"✅ Index created: {query[:50]}...")
            except Exception as e:
                print(f"❌ Index error: {e}")
        
        # Update existing data
        for query in update_queries:
            try:
                result = await conn.execute(text(query))
                print(f"✅ Updated {result.rowcount} rows")
            except Exception as e:
                print(f"❌ Update error: {e}")
    
    await engine.dispose()
    print("🚀 Migration fix completed!")

if __name__ == "__main__":
    asyncio.run(fix_migration())
