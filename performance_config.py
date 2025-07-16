"""
Performance configuration for ExfilEye DLP System
Optimized settings for better localhost performance
"""

# Performance settings
CACHE_TTL = 300  # 5 minutes cache
MAX_DISPLAY_RECORDS = None  # No limit on records shown in UI
CHART_ANIMATION_DISABLED = True  # Disable chart animations
LAZY_LOAD_THRESHOLD = 500  # Lazy load when > 500 records

# UI optimization settings
REDUCE_CSS_ANIMATIONS = True
OPTIMIZE_PLOTLY_CHARTS = True
BATCH_SIZE = 100  # Process data in batches

# Memory optimization
ENABLE_GARBAGE_COLLECTION = True
CLEAR_SESSION_ON_RELOAD = True

# Network analysis optimization
MAX_NETWORK_NODES = 200  # Limit network graph nodes
NETWORK_LAYOUT_CACHE = True

# CSV processing optimization
CHUNK_SIZE = 10000  # Process CSV in chunks
VALIDATE_ON_CHUNKS = True

# Chart optimization
CHART_RENDER_TIMEOUT = 30  # seconds
DISABLE_HOVER_ANIMATIONS = True
SIMPLIFIED_LEGENDS = True

# Database operations
BATCH_INSERT_SIZE = 1000
ASYNC_OPERATIONS = False  # Keep synchronous for simplicity