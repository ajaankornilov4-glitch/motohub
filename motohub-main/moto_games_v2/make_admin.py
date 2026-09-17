import sys
from app.db import init_db, conn

if len(sys.argv)!=2:
    print("Использование: python make_admin.py your@email.com")
    raise SystemExit(1)

init_db()
email=sys.argv[1].strip().lower()
c=conn()
c.execute("UPDATE users SET role='ADMIN' WHERE email=?",(email,))
c.commit()
print("ADMIN установлен для:", email)
c.close()
