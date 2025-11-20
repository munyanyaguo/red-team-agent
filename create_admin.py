#!/usr/bin/env python3
"""Create initial admin user"""
import sys
from app import create_app
from app.models import User, db

def create_admin():
    app = create_app()
    
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            print("✓ Admin user already exists!")
            print(f"  Username: {admin.username}")
            print(f"  Email: {admin.email}")
            print(f"  Role: {admin.role}")
            return
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@redteam.local',
            role='admin',
            is_active=True
        )
        admin.set_password('admin123')  # Change this password after first login!
        
        db.session.add(admin)
        db.session.commit()
        
        print("✓ Admin user created successfully!")
        print(f"  Username: admin")
        print(f"  Password: admin123")
        print(f"  Email: admin@redteam.local")
        print(f"  Role: admin")
        print("\n⚠️  IMPORTANT: Change the password after first login!")

if __name__ == '__main__':
    create_admin()
