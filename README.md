# wifi-crack

automated WPA2 handshake capture + dictionary crack for Linux Mint. plug in an alfa adapter and go.

## hardware needed

- **Alfa AWUS036ACHM** (~$35) or any adapter with monitor mode + packet injection

## setup (once)

```bash
sudo bash setup.sh
```

installs aircrack-ng, hashcat, hcxtools, and the rtl8812au driver. downloads rockyou.txt wordlist.

## run

```bash
sudo bash crack.sh
```

it will:
1. find your wireless adapter
2. put it in monitor mode
3. scan nearby networks (~15s)
4. you pick a target from the list
5. capture WPA2 handshake (deauths a client to force it)
6. if handshake fails, tries PMKID capture (no client needed)
7. cracks with rockyou.txt — hashcat (GPU) if available, aircrack-ng (CPU) as fallback

## config

edit the top of `crack.sh`:

| var | default | what |
|---|---|---|
| `SCAN_TIME` | 15 | seconds to scan for APs |
| `DEAUTH_PACKETS` | 10 | deauth frames to send |
| `CAPTURE_TIMEOUT` | 60 | seconds to wait for handshake |
| `WORDLIST` | `wordlists/rockyou.txt` | path to dictionary |

## custom wordlist

drop any `.txt` wordlist into `wordlists/` and update `WORDLIST` in crack.sh. bigger list = more coverage but slower.

for targeted attacks, generate a custom list:

```bash
# common patterns for ISP routers like Airtel
crunch 8 10 0123456789 -o wordlists/numbers_8-10.txt
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -t airtel@@ -o wordlists/airtel_pattern.txt
```

## output

captured handshakes and cracked hashes go in `captures/`.

## won't work if

- password isn't in the wordlist (use a bigger one or brute force with hashcat masks)
- WPA3/SAE network (resistant to offline dictionary attacks)
- no clients connected AND AP doesn't leak PMKID
- adapter doesn't support injection (get the alfa)

## notes

- only use on networks you own
- rockyou.txt covers ~14M common passwords. if the ISP set a random 8-digit default, you'll need `crunch` to generate a targeted numeric wordlist instead
- airtel routers often use 8-digit numeric passwords — `crunch 8 8 0123456789` generates all 100M combos, hashcat with a mid GPU eats that in under an hour
