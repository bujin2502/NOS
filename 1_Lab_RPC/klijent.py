import xmlrpc.client

try:
    symbolic_address, numeric_ip = input("Unesi adrese: ").split()

    server = xmlrpc.client.ServerProxy("http://localhost:8000")

    try:
        adresa_numericka = server.symbolic_to_numeric(symbolic_address)
        print(adresa_numericka)
    except xmlrpc.client.Fault as err:
        print(f"Greška u funkciji symbolic_to_numeric: {err}")
    
    try:
        adresa_simbolicka = server.numeric_to_symbolic(numeric_ip)
        print(adresa_simbolicka)
    except xmlrpc.client.Fault as err:
        print(f"Greška u funkciji numeric_to_symbolic: {err}")

except ValueError as ve:
    print(f"Greška: {ve}")
except Exception as e:
    print(f"Pojavila se neočekivana greška: {e}")
