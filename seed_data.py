"""
Seed Script — Pre-populate the database with all demo credentials.
Run once:  python seed_data.py
"""
import sqlite3, bcrypt

DATABASE = 'portal.db'

# ── Organization & Admin data ────────────────────────────────────────────────
ORGS = [
    {
        'name': 'MY TEST !',
        'admin_code': 'MY@TEST@!',
        'admin': {
            'full_name': 'Samanthula Eswar',
            'username': 'eswarS',
            'email': 'eswarsamanthulas@gmail.com',
            'password': 'EswarSamanthula@2005',
        },
        'students': [
            {'full_name': 'Eswar',  'username': 'Eswar_s',  'email': 'am.sc.u4cse23349@am.students.amrita.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Eswar@Secure1'},
            {'full_name': 'Vamsi',  'username': 'Vamsi_r',  'email': 'am.sc.u4cse23344@am.students.amrita.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Vamsi@Secure1'},
            {'full_name': 'Pavan',  'username': 'Pavan_s',  'email': 'am.sc.u4cse23350@am.students.amrita.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Pavan@Secure1'},
            {'full_name': 'Nandhu', 'username': 'Nandhu_s', 'email': 'am.sc.u4cse23353@am.students.amrita.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Nandhu@Secure1'},
            {'full_name': 'Zaid',   'username': 'Zaid_s',   'email': 'am.sc.u4cse23371@am.students.amrita.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Zaid@Secure1'},
        ],
    },
    {
        'name': 'Cyber Security Lab \u2014 S6 CSE D',
        'admin_code': 'CyberLab@SecureD6',
        'admin': {
            'full_name': 'Ravi Kumar Sharma',
            'username': 'ravikumar',
            'email': 'ravi.sharma@cselab.edu',
            'password': 'RaviKumar@123',
        },
        'students': [
            {'full_name': 'Samanthula Eswar',  'username': 'eswar_s',      'email': 'eswar.samanthula@student.edu', 'department': 'CSE', 'year': 'S6', 'password': 'Eswar@Secure1'},
            {'full_name': 'Advyth Reddy',      'username': 'advyth_r',     'email': 'advyth.reddy@student.edu',    'department': 'CSE', 'year': 'S6', 'password': 'Advyth@Secure2'},
            {'full_name': 'Bharath Chandra',    'username': 'bharath_c',    'email': 'bharath.chandra@student.edu',  'department': 'CSE', 'year': 'S6', 'password': 'Bharath@Secure3'},
            {'full_name': 'Chaitanya Varma',    'username': 'chaitanya_v',  'email': 'chaitanya.varma@student.edu',  'department': 'CSE', 'year': 'S6', 'password': 'Chaitanya@456'},
            {'full_name': 'Eati Harsha',        'username': 'eati_h',       'email': 'eati.harsha@student.edu',      'department': 'CSE', 'year': 'S6', 'password': 'Eati@Harsha99'},
            {'full_name': 'Guna Sekhar',        'username': 'guna_s',       'email': 'guna.sekhar@student.edu',      'department': 'CSE', 'year': 'S6', 'password': 'Guna@Portal7'},
        ],
    },
    {
        'name': 'Network Security Division \u2014 ECE',
        'admin_code': 'NetSec@Division2',
        'admin': {
            'full_name': 'Priya Nair',
            'username': 'priyanair',
            'email': 'priya.nair@netsec.edu',
            'password': 'PriyaNair@789',
        },
        'students': [
            {'full_name': 'Harsha Vardhan',  'username': 'harsha_v',     'email': 'harsha.vardhan@student.edu',  'department': 'ECE', 'year': 'S6', 'password': 'Harsha@Vard88'},
            {'full_name': 'Harshitha Reddy', 'username': 'harshitha_r',  'email': 'harshitha.reddy@student.edu', 'department': 'ECE', 'year': 'S6', 'password': 'Harshi@Secure5'},
            {'full_name': 'Jaswanth Rao',    'username': 'jaswanth_r',   'email': 'jaswanth.rao@student.edu',    'department': 'ECE', 'year': 'S6', 'password': 'Jaswanth@Rao1'},
            {'full_name': 'Kartheek Mudi',   'username': 'kartheek_m',   'email': 'kartheek.mudi@student.edu',   'department': 'ECE', 'year': 'S6', 'password': 'Kartheek@21!'},
            {'full_name': 'Kk Venkat',       'username': 'kk_venkat',    'email': 'kk.venkat@student.edu',       'department': 'ECE', 'year': 'S6', 'password': 'KkVenkat@99!'},
        ],
    },
    {
        'name': 'Ethical Hacking Club \u2014 ME Dept',
        'admin_code': 'EthHack@Club3X',
        'admin': {
            'full_name': 'Anand Subramanian',
            'username': 'anand_sub',
            'email': 'anand.sub@ethicalhack.edu',
            'password': 'Anand@EthHack1',
        },
        'students': [
            {'full_name': 'Kunal Mehta',  'username': 'kunal_m',  'email': 'kunal.mehta@student.edu',  'department': 'ME', 'year': 'S6', 'password': 'Kunal@Mehta77'},
            {'full_name': 'Manish Gupta', 'username': 'manish_g', 'email': 'manish.gupta@student.edu', 'department': 'ME', 'year': 'S6', 'password': 'Manish@Gupt55'},
            {'full_name': 'Nisha Patel',  'username': 'nisha_p',  'email': 'nisha.patel@student.edu',  'department': 'ME', 'year': 'S6', 'password': 'Nisha@Patel33'},
            {'full_name': 'Omkar Singh',  'username': 'omkar_s',  'email': 'omkar.singh@student.edu',  'department': 'ME', 'year': 'S4', 'password': 'Omkar@Singh12'},
        ],
    },
    {
        'name': 'InfoSec Research Group \u2014 CE Dept',
        'admin_code': 'InfoSec@ResGrp4',
        'admin': {
            'full_name': 'Deepika Menon',
            'username': 'deepika_m',
            'email': 'deepika.menon@infosec.edu',
            'password': 'Deepika@Info9!',
        },
        'students': [
            {'full_name': 'Pranav Iyer',   'username': 'pranav_i', 'email': 'pranav.iyer@student.edu',   'department': 'CE', 'year': 'S8', 'password': 'Pranav@Iyer44'},
            {'full_name': 'Qasim Khan',    'username': 'qasim_k',  'email': 'qasim.khan@student.edu',    'department': 'CE', 'year': 'S8', 'password': 'Qasim@Khan66!'},
            {'full_name': 'Ritika Sharma', 'username': 'ritika_s', 'email': 'ritika.sharma@student.edu', 'department': 'CE', 'year': 'S8', 'password': 'Ritika@Sha88!'},
            {'full_name': 'Sanjay Pillai', 'username': 'sanjay_p', 'email': 'sanjay.pillai@student.edu', 'department': 'CE', 'year': 'S4', 'password': 'Sanjay@Pill22'},
            {'full_name': 'Tanvi Desai',   'username': 'tanvi_d',  'email': 'tanvi.desai@student.edu',   'department': 'CE', 'year': 'S4', 'password': 'Tanvi@Desai11'},
        ],
    },
]


def hash_pw(plaintext):
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()


def seed():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys=ON")

    # Ensure tables exist (re-use same schema as app.py init_db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            admin_code_hash TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'student',
            full_name     TEXT DEFAULT '',
            department    TEXT DEFAULT 'CSE',
            year          TEXT DEFAULT 'S6',
            bio           TEXT DEFAULT '',
            org_id        INTEGER,
            is_locked     INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );
    """)
    db.commit()

    total_orgs = 0
    total_admins = 0
    total_students = 0

    for org_data in ORGS:
        # Check if org already exists
        existing = db.execute("SELECT id FROM organizations WHERE name=?", (org_data['name'],)).fetchone()
        if existing:
            print(f"  [SKIP] Org \"{org_data['name']}\" already exists.")
            continue

        # Create organization
        code_hash = hash_pw(org_data['admin_code'])
        db.execute("INSERT INTO organizations (name, admin_code_hash) VALUES (?,?)",
                   (org_data['name'], code_hash))
        db.commit()
        org_id = db.execute("SELECT id FROM organizations WHERE name=? ORDER BY id DESC LIMIT 1",
                            (org_data['name'],)).fetchone()[0]
        total_orgs += 1
        print(f"  [OK] Created org: \"{org_data['name']}\" (id={org_id})")

        # Create admin
        admin = org_data['admin']
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, role, full_name, org_id) VALUES (?,?,?,?,?,?)",
                (admin['username'], admin['email'], hash_pw(admin['password']),
                 'admin', admin['full_name'], org_id))
            db.commit()
            total_admins += 1
            print(f"     [OK] Admin: {admin['username']}")
        except Exception as e:
            print(f"     [SKIP] Admin {admin['username']}: {e}")

        # Create students
        for stu in org_data['students']:
            try:
                db.execute(
                    "INSERT INTO users (username, email, password_hash, role, full_name, department, year, org_id) VALUES (?,?,?,?,?,?,?,?)",
                    (stu['username'], stu['email'], hash_pw(stu['password']),
                     'student', stu['full_name'], stu['department'], stu['year'], org_id))
                db.commit()
                total_students += 1
                print(f"     [OK] Student: {stu['username']}")
            except Exception as e:
                print(f"     [SKIP] Student {stu['username']}: {e}")

    db.close()
    print(f"\n{'='*50}")
    print(f"  SEED COMPLETE")
    print(f"  Organizations : {total_orgs}")
    print(f"  Admins        : {total_admins}")
    print(f"  Students      : {total_students}")
    print(f"{'='*50}")


if __name__ == '__main__':
    print("="*50)
    print("  Seeding database with demo credentials...")
    print("="*50)
    seed()
