import streamlit as st
import pandas as pd
import ipaddress
import platform
import subprocess
import socket
import networkx as nx
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import time

# Configuration
DEFAULT_SUBNET = "192.168.1.0/24"


def is_valid_subnet(subnet: str) -> bool:
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def ping_host(ip: str) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=2)
        return True
    except:
        return False


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


class SimpleScanner:
    def scan_network(self, subnet: str):
        devices = []
        network = ipaddress.ip_network(subnet, strict=False)

        for ip in list(network.hosts())[:10]:  # Scan only first 10 for speed
            ip_str = str(ip)
            if ping_host(ip_str):
                devices.append({
                    'ip': ip_str,
                    'hostname': get_hostname(ip_str),
                    'status': '🟢 Online'
                })
        return devices


def create_network_topology(devices):
    """Create a network topology graph showing device connections"""
    if not devices:
        return None

    # Create a graph
    G = nx.Graph()

    # Add all devices as nodes
    for device in devices:
        G.add_node(device['ip'], hostname=device['hostname'])

    # Create connections - connect all devices in a star topology
    if len(devices) > 1:
        central_node = devices[0]['ip']
        for device in devices[1:]:
            G.add_edge(central_node, device['ip'])

    return G


def plot_network_graph(devices):
    """Create an interactive network topology graph using Plotly"""
    if not devices:
        st.warning("No devices to display in graph")
        return

    G = create_network_topology(devices)
    if not G:
        return

    try:
        pos = nx.spring_layout(G, k=1, iterations=50)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=2, color='#888'),
            hoverinfo='none',
            mode='lines'
        )

        node_x = []
        node_y = []
        node_text = []
        node_hover = []

        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append("🖥️")

            device_info = next((d for d in devices if d['ip'] == node), None)
            if device_info:
                node_hover.append(f"IP: {node}<br>Hostname: {device_info['hostname']}")
            else:
                node_hover.append(f"IP: {node}")

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="middle center",
            textfont=dict(size=20),
            marker=dict(
                size=40,
                color='lightblue',
                line=dict(width=2, color='darkblue')
            ),
            hovertext=node_hover
        )

        fig = go.Figure(data=[edge_trace, node_trace])

        fig.update_layout(
            title=dict(text='Network Topology', font=dict(size=20)),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=20, r=20, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white',
            height=500
        )

        st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        st.error(f"Error creating network graph: {str(e)}")


def display_text_topology(devices):
    """Display a simple text-based network topology"""
    if not devices:
        return

    st.subheader("Network Topology (Text View)")

    if len(devices) == 1:
        st.write(f"🖥️ Single device: {devices[0]['ip']} ({devices[0]['hostname']})")
    else:
        central_device = devices[0]
        st.write(f"🌐 Central Device (Router/Gateway): {central_device['ip']} ({central_device['hostname']})")
        st.write("📡 Connected Devices:")
        for device in devices[1:]:
            st.write(f"   ├── {device['ip']} ({device['hostname']})")

        st.info(f"**Network Summary:** {len(devices)} devices connected in star topology")


def main():
    st.set_page_config(
        page_title="Network Topology Visualizer",
        page_icon="🌐",
        layout="wide"
    )

    st.title("🌐 Network Topology Visualizer")
    st.markdown("A comprehensive tool to discover devices and visualize network topology")

    if 'devices' not in st.session_state:
        st.session_state.devices = []
    if 'scan_complete' not in st.session_state:
        st.session_state.scan_complete = False

    with st.sidebar:
        st.header("Scan Configuration")
        subnet = st.text_input("Network Subnet", DEFAULT_SUBNET)

        st.subheader("Visualization Options")
        viz_type = st.radio(
            "Graph Type",
            ["Interactive Graph", "Text Topology", "Both"],
            index=0
        )

        if st.button("Start Scan", use_container_width=True):
            if is_valid_subnet(subnet):
                with st.spinner("Scanning network..."):
                    scanner = SimpleScanner()
                    devices = scanner.scan_network(subnet)
                    st.session_state.devices = devices
                    st.session_state.scan_complete = True
                    st.rerun()
            else:
                st.error("Invalid subnet format!")

    if st.session_state.scan_complete:
        devices = st.session_state.devices

        if devices:
            st.success(f"Found {len(devices)} devices!")

            st.subheader("📊 Discovered Devices")
            df = pd.DataFrame([{
                'IP Address': d['ip'],
                'Hostname': d['hostname'],
                'Status': d['status']
            } for d in devices])
            st.dataframe(df, use_container_width=True)

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Devices", len(devices))
            col2.metric("Online Devices", len(devices))
            col3.metric("Network Size", f"{len(devices)} nodes")

            st.subheader("🌐 Network Topology")
            if viz_type in ["Interactive Graph", "Both"]:
                plot_network_graph(devices)
            if viz_type in ["Text Topology", "Both"]:
                display_text_topology(devices)

            if len(devices) > 1:
                st.info("💡 **Network Insight**: Star topology detected — one central device connected to others.")

        else:
            st.warning("No devices found. Try a different subnet or check your network connection.")
            st.info("""
            **Common issues:**
            - Make sure you're on the correct network
            - Try subnets like 192.168.0.0/24 or 10.0.0.0/24
            - Run the app as Administrator for better results
            - Check if your firewall is blocking network scans
            """)
    else:
        st.markdown("""
        ### Welcome to Network Topology Visualizer!

        Discover devices on your network and visualize how they're connected.

        **To get started:**
        1. Enter your network subnet in the sidebar  
        2. Choose visualization type  
        3. Click **Start Scan**  

        **Common subnets:**
        - 192.168.1.0/24  
        - 192.168.0.0/24  
        - 10.0.0.0/24  

        **Tip:** Run as Administrator for best performance.
        """)


if __name__ == "__main__":
    main()
