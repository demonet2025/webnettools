"""
Shared utility functions for routes
"""

import sqlite3

def init_database():
    """Initialize SQLite database for storing recent searches"""
    conn = sqlite3.connect('recent_searches.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recent_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            full_url TEXT NOT NULL,
            search_count INTEGER DEFAULT 1,
            last_searched TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_recent_search(domain, full_url):
    """Save or update a recent search"""
    try:
        conn = sqlite3.connect('recent_searches.db')
        cursor = conn.cursor()
        
        # Check if domain already exists
        cursor.execute('SELECT id, search_count FROM recent_searches WHERE domain = ?', (domain,))
        result = cursor.fetchone()
        
        if result:
            # Update existing record
            search_id, count = result
            cursor.execute('''
                UPDATE recent_searches 
                SET search_count = ?, last_searched = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (count + 1, search_id))
        else:
            # Insert new record
            cursor.execute('''
                INSERT INTO recent_searches (domain, full_url, search_count, last_searched)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
            ''', (domain, full_url))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving recent search: {e}")

def get_recent_searches(limit=10):
    """Get recent searches ordered by last_searched"""
    try:
        conn = sqlite3.connect('recent_searches.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT domain, full_url, search_count, last_searched
            FROM recent_searches 
            ORDER BY last_searched DESC 
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        
        return [{
            'domain': row[0],
            'full_url': row[1],
            'search_count': row[2],
            'last_searched': row[3]
        } for row in results]
    except Exception as e:
        print(f"Error getting recent searches: {e}")
        return []

def mask_domain(domain):
    """Mask domain for display (e.g., pixabay.com -> pix***.com)"""
    if len(domain) <= 3:
        return domain
    return domain[:3] + '***' + domain[domain.rfind('.'):]
