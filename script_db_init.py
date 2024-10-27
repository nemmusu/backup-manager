from bm import db, User, app

def create_admin():
    with app.app_context():
        username = input("Insert Admin username: ")
        password = input("Insert Admin password: ")

        if User.query.filter_by(username=username).first():
            print("Existing Admin!")
        else:
            admin = User(username=username, password=password, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("Admin created successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Tables created successfully!")
        create_admin()
