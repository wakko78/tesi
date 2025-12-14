#script python per testare la connessione al db.
#ip:10.22.255.235:5432
#user:postgres
#password:postgres
#db:tesi

from sqlalchemy import create_engine
try:
    # Crea la stringa di connessione per SQLAlchemy
    # utente:password@host:port/database
    connection_string = "postgresql://postgres:postgres@10.22.255.235:5432/tesi"
    engine = create_engine(connection_string)
   
    # Test della connessione
    with engine.connect() as connection:
        print("Connessione al database riuscita!")
       
except Exception as e:
    print(f"Errore durante la connessione al database: {e}")