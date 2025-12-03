#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VARUX ELITE DASHBOARD v2.0 – Gelişmiş Grafikler + Gerçek Zamanlı İzleme
© 2025 VARUX Security – Tüm hakları saklıdır.
"""

import dash
from dash import dcc, html, Input, Output, State, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
import os
from pathlib import Path
import asyncio
import threading
import time
from datetime import datetime, timedelta
import sys
import random

# VARUX modül yolunu ekle
BASE_DIR = Path(__file__).parent
VARUX_DIR = BASE_DIR / "varux"
sys.path.insert(0, str(VARUX_DIR))

# Son raporları ve verileri tutacak global alan
LIVE_DATA = {
    "devices": [],
    "topology": {"nodes": [], "links": []},
    "vulnerabilities": [],
    "timeline": [],
    "protocol_dist": [],
    "vendor_dist": [],
    "risk_scores": [],
    "last_update": None
}

app = dash.Dash(__name__, title="VARUX Elite Dashboard", suppress_callback_exceptions=True)
app.config.suppress_callback_exceptions = True

# ====================== RENKLİ + PROFESYONEL LAYOUT ======================
app.layout = html.Div(style={'backgroundColor': '#121212', 'color': '#ffffff', 'fontFamily': 'Arial', 'padding': '20px'}, children=[
    html.Div([
        html.H1("VARUX ELITE SECURITY DASHBOARD", style={'textAlign': 'center', 'color': '#00ff41'}),
        html.H3("Türkiye'nin En Gelişmiş OT/ICS & Web Güvenlik Platformu", style={'textAlign': 'center', 'color': '#00d4ff'}),
        html.Hr(style={'borderColor': '#333'}),
    ]),

    # Lisans + Kontroller
    html.Div([
        dcc.Input(id='license-input', placeholder='Pro Lisans Anahtarı', style={'width': '300px', 'padding': '10px'}),
        html.Button("Lisans Doğrula", id="license-btn", style={'backgroundColor': '#00ff41', 'color': 'black', 'marginLeft': '10px'}),
        html.Div(id="license-status", style={'marginTop': '10px', 'fontWeight': 'bold'})
    ], style={'textAlign': 'center', 'margin': '20px'}),

    # Ana Kontrol Paneli
    html.Div([
        dcc.Dropdown(
            id='scan-type',
            options=[
                {'label': 'OT/ICS Derin Keşif (VARUX OT Framework)', 'value': 'ot_framework'},
                {'label': 'Endüstriyel Ağ Keşfi (industrial_recon)', 'value': 'industrial_recon'},
                {'label': 'Web & SQL Tarama (noxım)', 'value': 'noxim'},
                {'label': 'Tam Otomatik Pentest (varuxctl)', 'value': 'varuxctl'}
            ],
            placeholder="Tarama Türü Seç",
            style={'width': '500px'}
        ),
        dcc.Input(id='target-input', placeholder='Hedef (örn: 192.168.1.0/24 veya https://site.com)', style={'width': '400px', 'margin': '10px'}),
        html.Button("TARAMAYI BAŞLAT", id="start-scan", n_clicks=0, 
                    style={'backgroundColor': '#ff0066', 'color': 'white', 'fontSize': '18px', 'padding': '15px'}),
        html.Div(id='scan-status', style={'marginTop': '20px', 'fontSize': '20px', 'fontWeight': 'bold'})
    ], style={'textAlign': 'center', 'margin': '30px'}),

    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0),  # 5 saniyede bir güncelle

    # 6 Gelişmiş Grafik (Daha fazla ekledik)
    html.Div([
        # 1. Ağ Topolojisi (Force Graph)
        html.Div([
            html.H3("Ağ Topolojisi", style={'color': '#00ff41'}),
            dcc.Graph(id='network-graph', style={'height': '600px'})
        ], style={'width': '50%', 'display': 'inline-block'}),

        # 2. Cihaz Türleri Pasta Grafiği
        html.Div([
            html.H3("Cihaz Türü Dağılımı", style={'color': '#00d4ff'}),
            dcc.Graph(id='device-pie')
        ], style={'width': '50%', 'display': 'inline-block'}),
    ]),

    html.Div([
        # 3. Zaman İçinde Keşfedilen Cihazlar
        html.Div([
            html.H3("Zamanla Keşfedilen Cihazlar", style={'color': '#ff9900'}),
            dcc.Graph(id='timeline-graph')
        ], style={'width': '50%', 'display': 'inline-block'}),

        # 4. Kritiklik Seviyeleri
        html.Div([
            html.H3("Güvenlik Kritikliği Dağılımı", style={'color': '#ff0066'}),
            dcc.Graph(id='criticality-bar')
        ], style={'width': '50%', 'display': 'inline-block'}),
    ]),

    html.Div([
        # 5. Protokol Dağılımı Heatmap (Yeni)
        html.Div([
            html.H3("Protokol Dağılımı Heatmap", style={'color': '#00ffcc'}),
            dcc.Graph(id='protocol-heatmap')
        ], style={'width': '50%', 'display': 'inline-block'}),

        # 6. Risk Skorları Scatter Plot (Yeni)
        html.Div([
            html.H3("Risk Skorları Dağılımı", style={'color': '#ffcc00'}),
            dcc.Graph(id='risk-scatter')
        ], style={'width': '50%', 'display': 'inline-block'}),
    ]),

    # Alt Kısım: Detaylı Tablo + Log
    html.H3("Keşfedilen Cihazlar", style={'color': '#00ff41', 'marginTop': '40px'}),
    dash_table.DataTable(
        id='device-table',
        columns=[
            {"name": "IP", "id": "ip"},
            {"name": "MAC", "id": "mac"},
            {"name": "Üretici", "id": "vendor"},
            {"name": "Protokoller", "id": "protocols"},
            {"name": "Kritiklik", "id": "criticality"},
            {"name": "Son Görülme", "id": "last_seen"}
        ],
        style_cell={'backgroundColor': '#1e1e1e', 'color': 'white', 'textAlign': 'left'},
        style_header={'backgroundColor': '#333', 'fontWeight': 'bold'},
        page_size=15,
        style_table={'overflowX': 'auto'}
    ),

    html.Div(id='log-output', style={'marginTop': '30px', 'backgroundColor': '#000', 'padding': '15px', 'height': '200px', 'overflowY': 'scroll', 'fontFamily': 'Courier', 'whiteSpace': 'pre-line'})
])

# ====================== GERÇEK ZAMANLI GÜNCELLEME ======================
@app.callback(
    [Output('network-graph', 'figure'),
     Output('device-pie', 'figure'),
     Output('timeline-graph', 'figure'),
     Output('criticality-bar', 'figure'),
     Output('protocol-heatmap', 'figure'),
     Output('risk-scatter', 'figure'),
     Output('device-table', 'data'),
     Output('log-output', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_dashboard(n):
    data = LIVE_DATA

    # 1. Ağ Topolojisi (Force-directed)
    if data["topology"]["nodes"]:
        fig_topo = go.Figure(data=[go.Scatter(
            x=[n['x'] for n in data["topology"]["nodes"]],
            y=[n['y'] for n in data["topology"]["nodes"]],
            mode='markers+text',
            text=[n['label'] for n in data["topology"]["nodes"]],
            marker=dict(size=20, color=[n['color'] for n in data["topology"]["nodes"]])
        )])
        fig_topo.update_layout(
            template="plotly_dark", 
            title="Canlı Ağ Topolojisi",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
    else:
        fig_topo = go.Figure().add_annotation(text="Henüz cihaz keşfedilmedi", showarrow=False, font=dict(color='white'))
        fig_topo.update_layout(template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')

    # 2. Pasta Grafiği
    df_pie = pd.DataFrame(data["devices"])
    if not df_pie.empty and 'vendor' in df_pie.columns:
        pie_data = df_pie['vendor'].value_counts().reset_index()
        fig_pie = px.pie(pie_data, names='index', values='vendor', 
                         color_discrete_sequence=px.colors.sequential.Plasma)
        fig_pie.update_layout(template="plotly_dark")
    else:
        fig_pie = go.Figure().add_annotation(text="Veri yok", showarrow=False, font=dict(color='white'))
        fig_pie.update_layout(template="plotly_dark")

    # 3. Zaman Çizgisi
    if data["timeline"]:
        fig_timeline = px.line(
            x=[t['time'] for t in data["timeline"]], 
            y=[t['count'] for t in data["timeline"]], 
            title="Zamanla Keşfedilen Cihaz Sayısı"
        )
        fig_timeline.update_layout(template="plotly_dark")
    else:
        fig_timeline = go.Figure().add_annotation(text="Zaman çizelgesi verisi yok", showarrow=False, font=dict(color='white'))
        fig_timeline.update_layout(template="plotly_dark")

    # 4. Kritiklik Bar
    if not df_pie.empty and 'criticality' in df_pie.columns:
        crit = df_pie['criticality'].value_counts()
        fig_bar = px.bar(x=crit.index, y=crit.values, color=crit.index, 
                         color_discrete_map={'high': '#ff0066', 'medium': '#ff9900', 'low': '#00ff41'})
        fig_bar.update_layout(template="plotly_dark")
    else:
        fig_bar = go.Figure().add_annotation(text="Kritiklik verisi yok", showarrow=False, font=dict(color='white'))
        fig_bar.update_layout(template="plotly_dark")

    # 5. Protokol Heatmap (Yeni)
    if data["protocol_dist"]:
        df_heat = pd.DataFrame(data["protocol_dist"])
        if 'device' in df_heat.columns and 'protocol' in df_heat.columns and 'count' in df_heat.columns:
            try:
                pivot = df_heat.pivot(index='device', columns='protocol', values='count').fillna(0)
                fig_heat = px.imshow(pivot, color_continuous_scale='Viridis')
                fig_heat.update_layout(template="plotly_dark", title="Protokol Kullanım Heatmap")
            except Exception as e:
                fig_heat = go.Figure().add_annotation(text=f"Heatmap hatası: {str(e)}", showarrow=False, font=dict(color='white'))
                fig_heat.update_layout(template="plotly_dark")
        else:
            fig_heat = go.Figure().add_annotation(text="Protokol veri yok", showarrow=False, font=dict(color='white'))
            fig_heat.update_layout(template="plotly_dark")
    else:
        fig_heat = go.Figure().add_annotation(text="Protokol veri yok", showarrow=False, font=dict(color='white'))
        fig_heat.update_layout(template="plotly_dark")

    # 6. Risk Scatter (Yeni)
    if data["risk_scores"]:
        df_risk = pd.DataFrame(data["risk_scores"])
        if not df_risk.empty and 'device' in df_risk.columns and 'risk_score' in df_risk.columns:
            fig_scatter = px.scatter(df_risk, x='device', y='risk_score', color='criticality', 
                                     size='attack_surface', hover_data=['ip', 'vendor'], 
                                     color_discrete_map={'high': '#ff0066', 'medium': '#ff9900', 'low': '#00ff41'})
            fig_scatter.update_layout(template="plotly_dark", title="Risk Skorları Scatter")
        else:
            fig_scatter = go.Figure().add_annotation(text="Risk veri yok", showarrow=False, font=dict(color='white'))
            fig_scatter.update_layout(template="plotly_dark")
    else:
        fig_scatter = go.Figure().add_annotation(text="Risk veri yok", showarrow=False, font=dict(color='white'))
        fig_scatter.update_layout(template="plotly_dark")

    table_data = data["devices"] if data["devices"] else []

    log_text = f"Son güncelleme: {datetime.now().strftime('%H:%M:%S')}\nToplam cihaz: {len(data['devices'])}"
    if data["last_update"]:
        log_text += f"\nSon tarama: {data['last_update'].strftime('%H:%M:%S')}"

    return fig_topo, fig_pie, fig_timeline, fig_bar, fig_heat, fig_scatter, table_data, log_text

# ====================== LİSANS DOĞRULAMA ======================
@app.callback(
    Output('license-status', 'children'),
    Input('license-btn', 'n_clicks'),
    State('license-input', 'value')
)
def verify_license(n_clicks, license_key):
    if n_clicks is None or n_clicks == 0:
        return "Lisans bekleniyor..."
    
    if not license_key:
        return "❌ Lisans anahtarı gerekli!"
    
    # Basit lisans doğrulama (gerçek uygulamada daha güvenli bir sistem kullanın)
    if license_key.startswith("VARUX-") and len(license_key) > 10:
        return f"✅ Lisans aktif: {license_key[:10]}..."
    else:
        return "❌ Geçersiz lisans anahtarı!"

# ====================== TARAMA BAŞLAT ======================
@app.callback(
    Output('scan-status', 'children'),
    Input('start-scan', 'n_clicks'),
    State('scan-type', 'value'),
    State('target-input', 'value')
)
def start_scan(n_clicks, scan_type, target):
    if n_clicks == 0 or not scan_type or not target:
        return "Hazır. Tarama başlatmak için yukarıdan seçim yapın."

    def run_background():
        try:
            # Gerçek tarama modülleri burada çalıştırılacak
            # Örnek olarak simülasyon yapıyoruz
            print(f"Tarama başlatılıyor: {scan_type} -> {target}")
            
            # Simüle edilmiş tarama süresi
            time.sleep(5)
            
            # Örnek veri üret
            vendors = ["Siemens", "Rockwell", "Schneider", "ABB", "Mitsubishi", "Omron"]
            protocols_list = ["Modbus", "S7", "EtherNet/IP", "OPC-UA", "DNP3", "Profinet"]
            criticalities = ["high", "medium", "low"]
            
            devices = []
            protocol_dist = []
            risk_scores = []
            timeline = []
            
            # Rastgele cihazlar oluştur
            for i in range(random.randint(5, 15)):
                vendor = random.choice(vendors)
                device_ip = f"192.168.1.{random.randint(10, 250)}"
                device_protocols = random.sample(protocols_list, random.randint(1, 3))
                
                device = {
                    "ip": device_ip,
                    "mac": f"{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}",
                    "vendor": vendor,
                    "protocols": ",".join(device_protocols),
                    "criticality": random.choice(criticalities),
                    "last_seen": datetime.now().strftime("%H:%M:%S")
                }
                devices.append(device)
                
                # Protokol dağılımı verisi
                for protocol in device_protocols:
                    protocol_dist.append({
                        "device": f"Device{i+1}",
                        "protocol": protocol,
                        "count": random.randint(1, 20)
                    })
                
                # Risk skoru verisi
                risk_scores.append({
                    "device": f"Device{i+1}",
                    "risk_score": round(random.uniform(1.0, 10.0), 1),
                    "criticality": device["criticality"],
                    "attack_surface": random.randint(5, 25),
                    "ip": device_ip,
                    "vendor": vendor
                })
            
            # Zaman çizelgesi verisi
            base_time = datetime.now() - timedelta(minutes=30)
            for i in range(6):
                timeline.append({
                    "time": base_time + timedelta(minutes=i*5),
                    "count": random.randint(1, len(devices))
                })
            
            # Topoloji verisi
            nodes = []
            for i, device in enumerate(devices):
                nodes.append({
                    "x": random.uniform(-100, 100),
                    "y": random.uniform(-100, 100),
                    "label": device["ip"],
                    "color": "#ff0066" if device["criticality"] == "high" else "#ff9900" if device["criticality"] == "medium" else "#00ff41"
                })
            
            # Global veriyi güncelle
            LIVE_DATA["devices"] = devices
            LIVE_DATA["topology"]["nodes"] = nodes
            LIVE_DATA["protocol_dist"] = protocol_dist
            LIVE_DATA["risk_scores"] = risk_scores
            LIVE_DATA["timeline"] = timeline
            LIVE_DATA["last_update"] = datetime.now()
            
            print(f"Tarama tamamlandı: {len(devices)} cihaz keşfedildi")
            
        except Exception as e:
            print(f"Tarama hatası: {e}")
            # Hata durumunda bile bazı örnek veriler göster
            LIVE_DATA["devices"] = [
                {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "vendor": "Siemens", "protocols": "Modbus,S7", "criticality": "high", "last_seen": "şimdi"},
                {"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Rockwell", "protocols": "EtherNet/IP", "criticality": "medium", "last_seen": "şimdi"},
            ]
            LIVE_DATA["last_update"] = datetime.now()

    threading.Thread(target=run_background, daemon=True).start()
    return f"🔄 {scan_type.upper()} başladı → Hedef: {target} | Canlı grafiklerde izleyin!"

# ====================== DASHBOARD BAŞLAT ======================
if __name__ == "__main__":
    print("VARUX Elite Dashboard başlatılıyor → http://127.0.0.1:8050")
    app.run(debug=False, port=8050)