"""
HASEEB AHMAD BITF24M001
Information Security Project
Replay Attack Simulation
"""
import bcrypt  # using salt hashing to avoid rainbow attack
import hashlib
import time
import os

# Colors
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def green(text): return f"{GREEN}{text}{RESET}"
def red(text):   return f"{RED}{text}{RESET}"


class ReplaySimulation:

    USER_DB = {
        "alice": bcrypt.hashpw("pass123".encode(), bcrypt.gensalt()),
        "bob": bcrypt.hashpw("hello456".encode(), bcrypt.gensalt()),
    }

    VALID_WINDOW = 10

    def __init__(self):
        self.wire = []
        self.used_nonces = set()

    def hash_password(self, password):
        return password.encode()

    def show_packet(self, packet):
        print("\n  --- PACKET ---")
        for key, value in packet.items():
            print(f"  {key}: {value}")
        print("  --------------\n")

    def reset_state(self):
        self.wire = []
        self.used_nonces = set()


    # SERVER METHODS PHASES (1-3)

    def server_phase1(self, packet):
        u = packet.get("username")
        h = packet.get("password_hash")

        if u in self.USER_DB and bcrypt.checkpw(h, self.USER_DB[u]):

            print(green("  [SERVER] Password correct. Access GRANTED."))
            return True

        print(red("  [SERVER] Wrong credentials. Access DENIED."))
        return False
    
    def server_phase2(self, packet):
        u  = packet.get("username")
        h  = packet.get("password_hash")
        ts = packet.get("timestamp")

        age = time.time() - ts
        print(f"  [SERVER] Packet age: {age:.2f}s | Allowed window: {self.VALID_WINDOW}s")

        if age > self.VALID_WINDOW:
            print(red("  [SERVER] Packet too old. REJECTED."))
            return False

        if u in self.USER_DB and bcrypt.checkpw(h, self.USER_DB[u]):

            print(green("  [SERVER] Timestamp OK + Password correct. Access GRANTED."))
            return True

        print(red("  [SERVER] Wrong credentials. Access DENIED."))
        return False
    
    def server_phase3(self, packet):
        u     = packet.get("username")
        h     = packet.get("password_hash")
        ts    = packet.get("timestamp")
        nonce = packet.get("nonce")

        age = time.time() - ts
        print(f"  [SERVER] Packet age: {age:.2f}s | Allowed window: {self.VALID_WINDOW}s")

        if age > self.VALID_WINDOW:
            print(red("  [SERVER] Packet expired. REJECTED."))
            return False

        if nonce in self.used_nonces:
            print(red("  [SERVER] Nonce already used! REPLAY ATTACK DETECTED. BLOCKED."))
            return False

        self.used_nonces.add(nonce)
        print("  [SERVER] Nonce accepted and stored.")

        if u in self.USER_DB and bcrypt.checkpw(h, self.USER_DB[u]):

            print(green("  [SERVER] Nonce OK + Password correct. Access GRANTED."))
            return True

        print(red("  [SERVER] Wrong credentials. Access DENIED."))
        return False
    
    # CLIENT
    def client_action(self, phase, auth_fn):
        print("\n  --- CLIENT LOGIN ---")

        username = input("  Enter username: ").strip()
        password = input("  Enter password: ").strip()

        
        if username not in self.USER_DB:
            print(red("  [CLIENT] Username does not exist."))
            return

        print(f"\n  [CLIENT] Attempting login as '{username}'...")

        packet = {
            "username": username,
            "password_hash": password.encode(),
        }

        if phase >= 2:
            packet["timestamp"] = round(time.time(), 4)

        if phase >= 3:
            packet["nonce"] = os.urandom(16).hex()

        print("  [CLIENT] Packet built:")
        self.show_packet(packet)

        self.wire.append(dict(packet))
        print(f"  [NETWORK] Packet sent. Attacker captured it. ({len(self.wire)} packet(s))")

        print("\n  [SERVER] Receiving packet...")
        auth_fn(packet)

    # ATTACKER
    def attacker_action(self, auth_fn):
        if not self.wire:
            print(red("  [ATTACKER] No packets available. Login first."))
            return

        print(f"\n  [ATTACKER] Captured packets: {len(self.wire)}")

        for i, pkt in enumerate(self.wire, 1):
            ts    = pkt.get("timestamp", "N/A")
            nonce = pkt.get("nonce", "N/A")
            print(f"  [{i}] user={pkt['username']}  timestamp={ts}  nonce={str(nonce)[:10]}...")

        choice = input(f"\n  Choose packet (1-{len(self.wire)}): ").strip()

        if not choice.isdigit() or not (1 <= int(choice) <= len(self.wire)):
            print(red("  Invalid choice."))
            return

        replayed = self.wire[int(choice) - 1]

        print("\n  [ATTACKER] Replaying packet:")
        self.show_packet(replayed)

        print("  [SERVER] Processing replayed packet...")
        result = auth_fn(replayed)

        if result:
            print(red("\n  [RESULT] ATTACK SUCCESSFUL!"))
        else:
            print(green("\n  [RESULT] ATTACK BLOCKED!"))
 
    # ADMIN
    def admin_action(self):
        print("\n  --- ADMIN VIEW ---")

        print("\n  Users:")
        for u in self.USER_DB:
            print(f"  - {u}")

        print("\n  Captured Packets:")
        for i, p in enumerate(self.wire, 1):
            print(f"  [{i}] {p}")

        print("\n  Used Nonces:")
        for n in self.used_nonces:
            print(f"  - {n}")

    # PHASE RUNNER
    def run_phase(self, phase_num, title, auth_fn, description):
        self.reset_state()

       
        print(f"  PHASE {phase_num}: {title}")
        print(f"  {description}")
       

        while True:
            print("\n  1. CLIENT")
            print("  2. ATTACKER")
            print("  3. ADMIN")
            print("  4. NEXT")

            choice = input("\n  Choose: ").strip()

            if choice == "1":
                self.client_action(phase_num, auth_fn)
            elif choice == "2":
                self.attacker_action(auth_fn)
            elif choice == "3":
                self.admin_action()
            elif choice == "4":
                break
            else:
                print(red("  Invalid input."))

   
    # MAIN FLOW
   

def main():
    sim = ReplaySimulation()

   
    print(BOLD+red("Replay Attack & Prevention".center(130)))
    print(BOLD+red("Using Timestamp and Nonce".center(130)))
   




    input("\nPress Enter for Phase 1...")
    sim.run_phase(1, "NO PROTECTION", sim.server_phase1,
                  "Replay attack always succeeds.")

    input("\nPress Enter for Phase 2...")
    sim.run_phase(2, "TIMESTAMP", sim.server_phase2,
                  "Old packets blocked, fast replay still works.")

    input("\nPress Enter for Phase 3...")
    sim.run_phase(3, "NONCE + TIMESTAMP", sim.server_phase3,
                  "All replay attacks blocked.")

if __name__ == "__main__":
    
    main()