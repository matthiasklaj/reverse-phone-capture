import pyshark
import ipinfo
import json

# Your IPinfo access token
ACCESS_TOKEN = 'your_ipinfo_access_token_here'

# Initialize IPinfo handler
handler = ipinfo.getHandler(ACCESS_TOKEN)

# File to store geolocation data
GEOLOCATION_FILE = 'geolocation_data.json'

# List to store geolocation data
geolocation_data = []

def get_geolocation(ip_address):
    try:
        details = handler.getDetails(ip_address)
        return {
            'ip': ip_address,
            'city': details.city,
            'region': details.region,
            'country': details.country,
            'lat': float(details.latitude),
            'lng': float(details.longitude)
        }
    except Exception as e:
        print(f"Error fetching geolocation for {ip_address}: {e}")
        return None

def analyze_packet(packet):
    # Check for SIP or RTP packets
    if 'sip' in packet or 'rtp' in packet:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            # Check if the IP address has already been processed
            if not any(d['ip'] == src_ip for d in geolocation_data):
                geo_data = get_geolocation(src_ip)
                if geo_data:
                    geolocation_data.append(geo_data)
            if not any(d['ip'] == dst_ip for d in geolocation_data):
                geo_data = get_geolocation(dst_ip)
                if geo_data:
                    geolocation_data.append(geo_data)
        except AttributeError:
            pass

def capture_live_traffic(interface='en0'):
    capture = pyshark.LiveCapture(interface=interface, display_filter='sip or rtp', bpf_filter='udp')
    print("Starting live VoIP packet capture...")

    for packet in capture.sniff_continuously():
        analyze_packet(packet)
        # Save the data after every packet for real-time updates
        with open(GEOLOCATION_FILE, 'w') as file:
            json.dump(geolocation_data, file)

if __name__ == '__main__':
    capture_live_traffic('en0')  # Replace 'en0' with your MacBook network interface
    # Final save of geolocation data
    with open(GEOLOCATION_FILE, 'w') as file:
        json.dump(geolocation_data, file)
    print("Geolocation data saved to geolocation_data.json")
