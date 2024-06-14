import os

def print_env_vars():
    for key, value in os.environ.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    print_env_vars()
