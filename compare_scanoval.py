import csv
from pathlib import Path
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog, messagebox

def select_file(title):
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title=title,
        filetypes=[("HTML файлы", "*.html"), ("Все файлы", "*.*")]
    )
    return file_path

def parse_vulnerabilities(html_path):
    with open(html_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')

    table = soup.find('table', class_='vulnerabilitiesTbl')
    if not table:
        raise ValueError(f"Таблица с уязвимостями не найдена в {html_path}")

    vulns = {}
    for row in table.find_all('tr'):
        bdu_cell = row.find('td', class_='bdu')
        if not bdu_cell:
            continue
        bdu = bdu_cell.get_text(strip=True)

        risk_cell = row.find('td', class_='risk riskTextColor')
        risk = "Неизвестно"
        if risk_cell:
            div = risk_cell.find('div')
            if div:
                risk = div.get_text(strip=True)

        desc_cell = row.find('td', class_='desc')
        desc = desc_cell.get_text(strip=True) if desc_cell else ""

        vulns[bdu] = (risk, desc)
    return vulns

def save_to_csv(data, filename):
    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['BDU', 'Уровень опасности', 'Название уязвимости'])
        for bdu, (risk, desc) in sorted(data.items()):
            writer.writerow([bdu, risk, desc])

def generate_html_report(fixed, remaining, before_count, after_count, output_html="comparison_report.html"):
    fixed_count = len(fixed)
    remaining_count = len(remaining)

    def generate_table(vulns_dict, table_id):
        if not vulns_dict:
            return "<p>Нет данных.</p>"
        rows = []
        for bdu, (risk, desc) in sorted(vulns_dict.items()):
            risk_class = "risk-low"
            if risk.startswith("Критический"):
                risk_class = "risk-critical"
            elif risk.startswith("Высокий"):
                risk_class = "risk-high"
            elif risk.startswith("Средний"):
                risk_class = "risk-medium"
            elif risk.startswith("Низкий"):
                risk_class = "risk-low"

            rows.append(f"""
        <tr>
            <td style="font-family: monospace;">{bdu}</td>
            <td><span class="{risk_class}">{risk}</span></td>
            <td>{desc[:200]}{"..." if len(desc)>200 else ""}</td>
        </tr>""")
        return f"""
        <div class="table-wrapper" id="{table_id}-wrapper">
            <div class="table-header">
                <button class="toggle-btn" onclick="toggleTable('{table_id}')">Свернуть</button>
            </div>
            <div class="table-container" id="{table_id}">
                <table>
                    <thead>
                        <tr><th>Идентификатор</th><th>Уровень опасности</th><th>Название уязвимости</th></tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """

    html_template = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчет по анализу уязвимостей</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 30px; background-color: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .stat-card {{ flex: 1; background: #f8f9fa; border-radius: 12px; padding: 15px; text-align: center; }}
        .stat-number {{ font-size: 36px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ font-size: 14px; color: #7f8c8d; margin-top: 8px; }}
        .fixed {{ border-left: 6px solid #2ecc71; }}
        .remaining {{ border-left: 6px solid #e74c3c; }}
        .section {{ margin-top: 40px; }}
        .section h2 {{ border-bottom: 2px solid #ddd; padding-bottom: 8px; }}
        footer {{ text-align: center; font-size: 12px; color: #aaa; margin-top: 30px; }}

        .table-wrapper {{
            margin-bottom: 20px;
        }}
        .table-header {{
            margin-top: 10px;
            margin-bottom: 5px;
        }}
        .toggle-btn {{
            background-color: #34495e;
            color: white;
            border: none;
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}
        .toggle-btn:hover {{
            background-color: #2c3e50;
        }}
        .table-container {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            background-color: #34495e;
            color: white;
            padding: 12px 8px;
            text-align: left;
        }}
        td {{
            border: 1px solid #ddd;
            padding: 8px;
            vertical-align: top;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .risk-critical {{ background-color: #89171A; color: white; padding: 2px 8px; border-radius: 12px; display: inline-block; font-size: 12px; }}
        .risk-high {{ background-color: #CC0000; color: white; padding: 2px 8px; border-radius: 12px; display: inline-block; font-size: 12px; }}
        .risk-medium {{ background-color: #F5770F; color: white; padding: 2px 8px; border-radius: 12px; display: inline-block; font-size: 12px; }}
        .risk-low {{ background-color: #00705C; color: white; padding: 2px 8px; border-radius: 12px; display: inline-block; font-size: 12px; }}
    </style>
    <script>
        function toggleTable(tableId) {{
            var container = document.getElementById(tableId);
            var btn = event.target;
            if (container.style.display === "none") {{
                container.style.display = "block";
                btn.textContent = "Свернуть";
            }} else {{
                container.style.display = "none";
                btn.textContent = "Развернуть";
            }}
        }}
    </script>
</head>
<body>
<div class="container">
    <h1>Сравнение отчётов ScanOval</h1>
    <div class="stats">
        <div class="stat-card fixed">
            <div class="stat-number">{before_count}</div>
            <div class="stat-label">Уязвимостей до устранения</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{after_count}</div>
            <div class="stat-label">Уязвимостей после устранения</div>
        </div>
        <div class="stat-card fixed">
            <div class="stat-number">{fixed_count}</div>
            <div class="stat-label">Устранено</div>
        </div>
        <div class="stat-card remaining">
            <div class="stat-number">{remaining_count}</div>
            <div class="stat-label">Осталось</div>
        </div>
    </div>
    <div class="section">
        <h2>Устранённые уязвимости ({fixed_count})</h2>
        {generate_table(fixed, "fixed-table")}
    </div>
    <div class="section">
        <h2>Оставшиеся уязвимости ({remaining_count})</h2>
        {generate_table(remaining, "remaining-table")}
    </div>
    <footer>Сгенерировано инструментом сравнения ScanOval</footer>
</div>
<script>
    // Инициализация: все таблицы развёрнуты по умолчанию
    document.querySelectorAll('.table-container').forEach(function(container) {{
        container.style.display = 'block';
    }});
</script>
</body>
</html>"""
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_template)
    return output_html

def main():
    before_path = select_file("Выберите HTML-отчёт ДО устранения уязвимостей")
    if not before_path:
        messagebox.showerror("Ошибка", "Файл не выбран.")
        return

    after_path = select_file("Выберите HTML-отчёт ПОСЛЕ устранения уязвимостей")
    if not after_path:
        messagebox.showerror("Ошибка", "Файл не выбран.")
        return

    try:
        before = parse_vulnerabilities(before_path)
        after = parse_vulnerabilities(after_path)
    except Exception as e:
        messagebox.showerror("Ошибка парсинга", str(e))
        return

    fixed = {bdu: before[bdu] for bdu in before if bdu not in after}
    remaining = {bdu: before[bdu] for bdu in before if bdu in after}
    new = {bdu: after[bdu] for bdu in after if bdu not in before}

    if fixed:
        save_to_csv(fixed, "fixed_vulnerabilities.csv")
    if remaining:
        save_to_csv(remaining, "remaining_vulnerabilities.csv")
    if new:
        save_to_csv(new, "new_vulnerabilities.csv")

    html_file = generate_html_report(fixed, remaining, len(before), len(after), "comparison_report.html")

    summary = f"Сравнение завершено.\nУстранено: {len(fixed)}\nОсталось: {len(remaining)}\n\nСозданы файлы:\n"
    if fixed:
        summary += "  fixed_vulnerabilities.csv\n"
    if remaining:
        summary += "  remaining_vulnerabilities.csv\n"
    if new:
        summary += "  new_vulnerabilities.csv\n"
    summary += f"  {html_file}"

    messagebox.showinfo("Готово", summary)

if __name__ == "__main__":
    main()