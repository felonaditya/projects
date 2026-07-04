import random

def generate_tlp(count=10):
    print(f"Generating {count} random TLPs...")
    for i in range(count):
        tlp_type = random.choice(["MRd", "MW r", "CplD"])
        print(f"TLP {i}: Type={tlp_type}, Length={random.randint(1,512)}")

if __name__ == "__main__":
    generate_tlp(20)