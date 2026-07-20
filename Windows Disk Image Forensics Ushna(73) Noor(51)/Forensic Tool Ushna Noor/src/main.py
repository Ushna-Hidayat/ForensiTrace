# ============================================================
#  main.py  –  ForensiTrace GUI (Tkinter)
#  Course  : CSDF-30117  Introduction to Digital Forensics
#  Authors : Ushna Hidayat | Noor Fatima
#  Version : 2.0  |  Spring 2026
# ============================================================

import os, sys, json, datetime, threading, tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from analyzer import (
    TimelineAnalyzer, FileMetadataExtractor, HashVerifier,
    ForensicReportBuilder, BrowserHistoryAnalyzer, EmailHeaderAnalyzer,
    WindowsEventLogParser, SteganographyDetector,
    USBActivityMonitor, MemoryDumpAnalyzer, DeletedFileScanner,
    PasswordStrengthChecker, NetworkPacketAnalyzer, FileIntegrityMonitor,
    MalwareHashLookup, KeywordSearcher, TimelineChartGenerator, ExcelExporter
)

# ── Theme ────────────────────────────────────────────────────
C = {
    'bg':'#0d1117','panel':'#161b22','sidebar':'#0a0d13',
    'border':'#30363d','accent':'#1f6feb','accent2':'#58a6ff',
    'success':'#3fb950','warn':'#d29922','danger':'#f85149',
    'text':'#e6edf3','muted':'#8b949e',
}
FM = ('Consolas',9); FB = ('Segoe UI',9); FBD = ('Segoe UI Semibold',9)
FT = ('Segoe UI Light',17); FH2 = ('Segoe UI Semibold',11)

# ── Widget helpers ───────────────────────────────────────────
def mbtn(parent, text, cmd, color=None, width=16):
    bg = color or C['accent']
    b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=C['text'],
                  relief='flat', font=FBD, padx=10, pady=6,
                  cursor='hand2', width=width, bd=0,
                  activebackground=C['accent2'], activeforeground='white')
    b.bind('<Enter>', lambda e: b.config(bg=C['accent2']))
    b.bind('<Leave>', lambda e: b.config(bg=bg))
    return b

def mcard(parent, **kw):
    kw.setdefault('bg', C['panel']); kw.setdefault('relief','flat')
    kw.setdefault('highlightbackground', C['border']); kw.setdefault('highlightthickness',1)
    return tk.Frame(parent, **kw)

def mlog(parent):
    b = scrolledtext.ScrolledText(
        parent, font=FM, bg=C['panel'], fg=C['text'],
        insertbackground=C['text'], relief='flat', bd=0,
        highlightthickness=1, highlightbackground=C['border'], state='disabled')
    return b

def mlog_write(box, msg):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    box.config(state='normal')
    box.insert('end', f'[{ts}]  {msg}\n')
    box.see('end'); box.config(state='disabled')

def mtree(parent):
    style = ttk.Style(); style.theme_use('clam')
    style.configure('FT.Treeview', background=C['panel'], foreground=C['text'],
                    rowheight=24, font=FM, fieldbackground=C['panel'], borderwidth=0)
    style.configure('FT.Treeview.Heading', background=C['sidebar'],
                    foreground=C['accent2'], font=FBD, relief='flat')
    style.map('FT.Treeview', background=[('selected', C['accent'])])
    tv = ttk.Treeview(parent, style='FT.Treeview', selectmode='browse', show='headings')
    tv.tag_configure('red', foreground=C['danger'])
    tv.tag_configure('warn', foreground=C['warn'])
    return tv

def scrolled_tree(parent):
    f = tk.Frame(parent, bg=C['bg'])
    tv = mtree(f)
    vsb = ttk.Scrollbar(f, orient='vertical', command=tv.yview)
    hsb = ttk.Scrollbar(f, orient='horizontal', command=tv.xview)
    tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    vsb.pack(side='right', fill='y'); hsb.pack(side='bottom', fill='x')
    tv.pack(fill='both', expand=True)
    return f, tv

def file_row(parent, label, var, cmd):
    f = tk.Frame(parent, bg=C['panel']); f.pack(fill='x', pady=3)
    tk.Label(f, text=label, font=FBD, bg=C['panel'], fg=C['muted'],
             width=20, anchor='w').pack(side='left')
    tk.Entry(f, textvariable=var, font=FM, bg=C['bg'], fg=C['text'],
             insertbackground=C['text'], relief='flat', bd=0, width=52,
             highlightthickness=1, highlightbackground=C['border']
             ).pack(side='left', padx=6, ipady=4)
    mbtn(f, '📂 Browse', cmd, width=10).pack(side='left')

# ─────────────────────────────────────────────────────────────
class ForensiTraceApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title('ForensiTrace v2.0  ·  Digital Forensic Investigation System')
        self.geometry('1360x840'); self.minsize(1100,700); self.configure(bg=C['bg'])

        # State vars
        self.csv_path=tk.StringVar(); self.file_path=tk.StringVar()
        self.hash_path=tk.StringVar(); self.hash_expected=tk.StringVar()
        self.hash_algo=tk.StringVar(value='SHA256')
        self.case_id=tk.StringVar(); self.investigator=tk.StringVar()
        self.stego_path=tk.StringVar(); self.evtx_path=tk.StringVar()
        self.dump_path=tk.StringVar()

        # Analysis results
        self._analyzer=None; self._timeline=[]; self._meta_result={}
        self._browser_result={}; self._email_result={}
        self._evtlog_result=[]; self._evtlog_parser=None
        self._stego_result={}; self._usb_result={}
        self._mem_result={}; self._del_result={}

        self._build_ui()
        self._show_tab('dashboard')

    # ── UI Skeleton ──────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        body = tk.Frame(self, bg=C['bg']); body.pack(fill='both', expand=True)
        self._build_sidebar(body)
        self._content = tk.Frame(body, bg=C['bg'])
        self._content.pack(side='left', fill='both', expand=True, padx=10, pady=10)

        self._pages = {}
        for name, builder in [
            ('dashboard', self._page_dashboard), ('timeline',  self._page_timeline),
            ('metadata',  self._page_metadata),  ('hash',      self._page_hash),
            ('browser',   self._page_browser),   ('email',     self._page_email),
            ('eventlog',  self._page_eventlog),  ('stego',     self._page_stego),
            ('usb',       self._page_usb),       ('memory',    self._page_memory),
            ('deleted',   self._page_deleted),
            ('password',  self._page_password),  ('network',   self._page_network),
            ('integrity', self._page_integrity), ('vtlookup',  self._page_vtlookup),
            ('keyword',   self._page_keyword),   ('charts',    self._page_charts),
            ('report',    self._page_report),
        ]:
            p = tk.Frame(self._content, bg=C['bg'])
            builder(p); self._pages[name] = p

    def _build_header(self):
        h = tk.Frame(self, bg=C['sidebar'],
                     highlightbackground=C['border'], highlightthickness=1)
        h.pack(fill='x')
        lg = tk.Frame(h, bg=C['sidebar']); lg.pack(side='left', padx=16, pady=8)
        tk.Label(lg, text='🔍', font=('Segoe UI',18), bg=C['sidebar'],
                 fg=C['accent2']).pack(side='left')
        tk.Label(lg, text=' ForensiTrace', font=('Segoe UI Semibold',15),
                 bg=C['sidebar'], fg=C['text']).pack(side='left')
        tk.Label(lg, text='  Digital Forensic Investigation System v2.0',
                 font=FB, bg=C['sidebar'], fg=C['muted']).pack(side='left')
        self._clock = tk.Label(h, text='', font=FM, bg=C['sidebar'], fg=C['muted'])
        self._clock.pack(side='right', padx=16); self._tick()
        info = tk.Frame(h, bg=C['sidebar']); info.pack(side='right', padx=16)
        for lbl, var in [('Case ID', self.case_id),('Investigator', self.investigator)]:
            tk.Label(info, text=lbl+':', font=FBD, bg=C['sidebar'],
                     fg=C['muted']).pack(side='left', padx=(0,2))
            tk.Entry(info, textvariable=var, font=FB, bg=C['panel'], fg=C['text'],
                     insertbackground=C['text'], relief='flat', bd=0, width=14,
                     highlightthickness=1, highlightbackground=C['border']
                     ).pack(side='left', padx=(0,10), ipady=3)

    def _tick(self):
        self._clock.config(text=datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S'))
        self.after(1000, self._tick)

    def _build_sidebar(self, parent):
        # Outer frame (fixed width)
        sb_outer = tk.Frame(parent, bg=C['sidebar'], width=215,
                            highlightbackground=C['border'], highlightthickness=1)
        sb_outer.pack(side='left', fill='y'); sb_outer.pack_propagate(False)

        # Canvas + scrollbar for scrollable sidebar
        sb_canvas = tk.Canvas(sb_outer, bg=C['sidebar'], width=213,
                              highlightthickness=0, bd=0)
        sb_scroll = ttk.Scrollbar(sb_outer, orient='vertical', command=sb_canvas.yview)
        sb_canvas.configure(yscrollcommand=sb_scroll.set)
        sb_scroll.pack(side='right', fill='y')
        sb_canvas.pack(side='left', fill='both', expand=True)

        # Inner frame inside canvas
        sb = tk.Frame(sb_canvas, bg=C['sidebar'])
        sb_win = sb_canvas.create_window((0,0), window=sb, anchor='nw')

        def _on_sb_configure(e):
            sb_canvas.configure(scrollregion=sb_canvas.bbox('all'))
            sb_canvas.itemconfig(sb_win, width=sb_canvas.winfo_width())
        sb.bind('<Configure>', _on_sb_configure)

        # Mouse wheel scroll
        def _on_mousewheel(e):
            sb_canvas.yview_scroll(int(-1*(e.delta/120)), 'units')
        sb_canvas.bind_all('<MouseWheel>', _on_mousewheel)

        groups = [
            ('CORE', [('dashboard','⊞  Dashboard'),('timeline','📅  Timeline Analyzer'),
                      ('metadata','🖼  File / Image Metadata'),('hash','🔒  Hash Verifier')]),
            ('ADVANCED', [('browser','🌐  Browser History'),('email','📧  Email Analyzer'),
                          ('eventlog','🖥  Event Log Parser'),('stego','🔑  Steganography'),
                          ('usb','📱  USB Monitor'),('memory','🧠  Memory Dump'),
                          ('deleted','🗑  Deleted Files')]),
            ('TOOLS', [
                ('password', '🔐  Password Checker'),
                ('network',  '📡  Packet Analyzer'),
                ('integrity','🛡  File Integrity Monitor'),
                ('vtlookup', '🦠  Malware Hash Lookup'),
                ('keyword',  '🔎  Keyword Search'),
                ('charts',   '📊  Timeline Charts'),
            ]),
            ('OUTPUT', [('report','📄  Report Generator')]),
        ]
        self._nav_btns = {}
        for grp, items in groups:
            tk.Label(sb, text=grp, font=('Segoe UI Semibold',7),
                     bg=C['sidebar'], fg=C['muted'], padx=14, pady=8).pack(anchor='w')
            for key, label in items:
                b = tk.Button(sb, text=label, font=FB, bg=C['sidebar'], fg=C['text'],
                              relief='flat', anchor='w', padx=14, pady=8,
                              cursor='hand2', bd=0, activebackground=C['panel'],
                              command=lambda k=key: self._show_tab(k))
                b.pack(fill='x'); self._nav_btns[key] = b
        tk.Label(sb, text='IUB · CSDF-30117 · Spring 2026',
                 font=('Segoe UI',7), bg=C['sidebar'], fg=C['muted']).pack(pady=8)

    def _show_tab(self, name):
        for k, b in self._nav_btns.items():
            b.config(bg=C['panel'] if k==name else C['sidebar'],
                     fg=C['accent2'] if k==name else C['text'])
        for k, p in self._pages.items():
            if k == name: p.pack(fill='both', expand=True)
            else: p.pack_forget()

    # ═══════════════════════════════════════════════════════
    #  PAGE 1 — DASHBOARD
    # ═══════════════════════════════════════════════════════
    def _page_dashboard(self, parent):
        tk.Label(parent, text='Dashboard', font=FT, bg=C['bg'], fg=C['text']
                 ).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='ForensiTrace v2.0  ·  18 Forensic Modules  ·  Ushna Hidayat | Noor Fatima',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,12))

        row = tk.Frame(parent, bg=C['bg']); row.pack(fill='x', pady=(0,12))
        self._stat_cards = {}
        for key, lbl, col in [('total_records','Total CSV Records',C['accent2']),
                                ('suspicious_files','Suspicious Files',C['danger']),
                                ('anomalies','Anomalies',C['warn'])]:
            c = mcard(row, padx=16, pady=14); c.pack(side='left', padx=(0,10), ipadx=8)
            tk.Label(c, text=lbl, font=FB, bg=C['panel'], fg=C['muted']).pack(anchor='w')
            lw = tk.Label(c, text='—', font=('Segoe UI Semibold',26), bg=C['panel'], fg=col)
            lw.pack(anchor='w'); self._stat_cards[key] = lw

        tk.Label(parent, text='Quick Launch', font=FH2, bg=C['bg'],
                 fg=C['accent2']).pack(anchor='w', pady=(4,8))
        grid = tk.Frame(parent, bg=C['bg']); grid.pack(fill='x')
        actions = [
            ('📂 Load CSV',        lambda: self._browse_csv(switch=True)),
            ('🌐 Browser History', lambda: self._show_tab('browser')),
            ('📧 Email Analyzer',  lambda: self._show_tab('email')),
            ('🖥 Event Logs',      lambda: self._show_tab('eventlog')),
            ('🔑 Steganography',   lambda: self._show_tab('stego')),
            ('📱 USB Monitor',     lambda: self._show_tab('usb')),
            ('🧠 Memory Dump',     lambda: self._show_tab('memory')),
            ('🗑 Deleted Files',   lambda: self._show_tab('deleted')),
            ('📄 Generate Report', lambda: self._show_tab('report')),
            ('🔐 Password Check',  lambda: self._show_tab('password')),
            ('📡 Packet Analyzer', lambda: self._show_tab('network')),
            ('🦠 Malware Lookup',  lambda: self._show_tab('vtlookup')),
            ('🔎 Keyword Search',  lambda: self._show_tab('keyword')),
            ('📊 Charts',          lambda: self._show_tab('charts')),
        ]
        for i,(lbl,cmd) in enumerate(actions):
            col = C['success'] if 'Report' in lbl else C['accent']
            mbtn(grid,lbl,cmd,color=col,width=20).grid(
                row=i//3, column=i%3, padx=6, pady=4, sticky='w')

        tk.Label(parent, text='Activity Log', font=FH2, bg=C['bg'],
                 fg=C['accent2']).pack(anchor='w', pady=(12,4))
        self._log = mlog(parent); self._log.pack(fill='both', expand=True)
        mlog_write(self._log, 'ForensiTrace v2.0 ready. 18 forensic modules loaded.')

    def _log_write(self, msg): mlog_write(self._log, msg)

    # ═══════════════════════════════════════════════════════
    #  PAGE 2 — TIMELINE
    # ═══════════════════════════════════════════════════════
    def _page_timeline(self, parent):
        tk.Label(parent, text='Timeline Analyzer', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=10, pady=10); top.pack(fill='x', pady=(0,8))
        file_row(top, 'Autopsy CSV:', self.csv_path, self._browse_csv)
        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(6,0))
        mbtn(br,'▶ Analyse',self._run_analysis,width=14).pack(side='left',padx=(0,6))
        mbtn(br,'⚠ Suspicious Only',self._show_suspicious,color=C['warn'],width=18).pack(side='left',padx=(0,6))
        mbtn(br,'↺ Show All',self._show_all,width=12).pack(side='left')

        ff = tk.Frame(parent, bg=C['bg']); ff.pack(fill='x', pady=(0,6))
        tk.Label(ff, text='Filter:', font=FBD, bg=C['bg'], fg=C['muted']).pack(side='left', padx=(0,4))
        self._filter_var = tk.StringVar()
        fe = tk.Entry(ff, textvariable=self._filter_var, font=FM,
                      bg=C['panel'], fg=C['text'], insertbackground=C['text'],
                      relief='flat', bd=0, width=50,
                      highlightthickness=1, highlightbackground=C['border'])
        fe.pack(side='left', ipady=4)
        fe.bind('<KeyRelease>', lambda e: self._apply_filter())

        f, self._tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._tl_status = tk.Label(parent, text='No data loaded.',
                                   font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._tl_status.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 3 — METADATA
    # ═══════════════════════════════════════════════════════
    def _page_metadata(self, parent):
        tk.Label(parent, text='File & Image Metadata Analyzer', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=10, pady=10); top.pack(fill='x', pady=(0,8))
        file_row(top, 'File Path:', self.file_path, self._browse_file)
        mbtn(top,'🔎 Analyze',self._run_metadata,width=14).pack(anchor='w', pady=(6,0))

        mid = tk.Frame(parent, bg=C['bg']); mid.pack(fill='both', expand=True)
        lf = mcard(mid, padx=12, pady=12); lf.pack(side='left', fill='both', expand=True, padx=(0,6))
        tk.Label(lf, text='📋 File Information', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._meta_text = mlog(lf); self._meta_text.pack(fill='both', expand=True)

        rf = mcard(mid, padx=12, pady=12); rf.pack(side='left', fill='both', expand=True)
        tk.Label(rf, text='📷 EXIF / GPS Data', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._exif_text = mlog(rf); self._exif_text.pack(fill='both', expand=True)

        self._meta_warn = tk.Label(parent, text='', font=FBD,
                                   bg=C['bg'], fg=C['danger'], anchor='w')
        self._meta_warn.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 4 — HASH
    # ═══════════════════════════════════════════════════════
    def _page_hash(self, parent):
        tk.Label(parent, text='Hash Verifier', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,8))
        c1 = mcard(parent, padx=12, pady=12); c1.pack(fill='x', pady=(0,8))
        file_row(c1, 'File Path:', self.hash_path, self._browse_hash_file)
        ef = tk.Frame(c1, bg=C['panel']); ef.pack(fill='x', pady=3)
        tk.Label(ef, text='Expected Hash:', font=FBD, bg=C['panel'],
                 fg=C['muted'], width=20, anchor='w').pack(side='left')
        tk.Entry(ef, textvariable=self.hash_expected, font=FM,
                 bg=C['bg'], fg=C['text'], insertbackground=C['text'],
                 relief='flat', bd=0, width=52,
                 highlightthickness=1, highlightbackground=C['border']
                 ).pack(side='left', padx=6, ipady=4)
        af = tk.Frame(c1, bg=C['panel']); af.pack(fill='x', pady=3)
        tk.Label(af, text='Algorithm:', font=FBD, bg=C['panel'],
                 fg=C['muted'], width=20, anchor='w').pack(side='left')
        for alg in ('MD5','SHA1','SHA256'):
            tk.Radiobutton(af, text=alg, variable=self.hash_algo, value=alg,
                           font=FB, bg=C['panel'], fg=C['text'],
                           selectcolor=C['bg'], activebackground=C['panel']
                           ).pack(side='left', padx=8)
        br = tk.Frame(c1, bg=C['panel']); br.pack(fill='x', pady=(8,0))
        mbtn(br,'▶ Compute',self._run_hash_compute,width=14).pack(side='left',padx=(0,6))
        mbtn(br,'✔ Verify',self._run_hash_verify,color=C['success'],width=12).pack(side='left')

        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='Results', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._hash_text = mlog(res); self._hash_text.pack(fill='both', expand=True)
        self._hash_result_lbl = tk.Label(parent, text='', font=FH2, bg=C['bg'], anchor='w')
        self._hash_result_lbl.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 5 — BROWSER HISTORY
    # ═══════════════════════════════════════════════════════
    def _page_browser(self, parent):
        tk.Label(parent, text='Browser History & Cache', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Auto-scans Chrome, Edge, and Firefox on this PC.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        mbtn(top,'🌐 Scan All Browsers',self._run_browser,width=24).pack(anchor='w')

        self._browser_nb = ttk.Notebook(parent); self._browser_nb.pack(fill='both', expand=True)
        tab_keys = [('chrome_history','Chrome History'),('chrome_downloads','Chrome Downloads'),
                    ('chrome_searches','Chrome Searches'),('edge_history','Edge History'),
                    ('edge_downloads','Edge Downloads'),('firefox_history','Firefox History'),
                    ('firefox_downloads','Firefox Downloads')]
        self._brow_tabs = {}
        for key, label in tab_keys:
            f = tk.Frame(self._browser_nb, bg=C['panel'])
            self._browser_nb.add(f, text=label)
            t = mlog(f); t.pack(fill='both', expand=True, padx=4, pady=4)
            self._brow_tabs[key] = t

        self._browser_status = tk.Label(parent, text='Not scanned yet.',
                                        font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._browser_status.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 6 — EMAIL ANALYZER
    # ═══════════════════════════════════════════════════════
    def _page_email(self, parent):
        tk.Label(parent, text='Email Header Analyzer', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Paste raw email headers to detect spoofing, trace IPs, check SPF/DKIM.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        pane = tk.Frame(parent, bg=C['bg']); pane.pack(fill='both', expand=True)

        lf = mcard(pane, padx=10, pady=10); lf.pack(side='left', fill='both', expand=True, padx=(0,6))
        tk.Label(lf, text='📥 Paste Raw Email Headers:', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,4))
        self._email_input = scrolledtext.ScrolledText(
            lf, font=FM, bg=C['bg'], fg=C['text'],
            insertbackground=C['text'], relief='flat', bd=0, height=20,
            highlightthickness=1, highlightbackground=C['border'])
        self._email_input.pack(fill='both', expand=True)
        mbtn(lf,'🔍 Analyze Headers',self._run_email,width=22).pack(anchor='w', pady=(8,0))

        rf = mcard(pane, padx=10, pady=10); rf.pack(side='left', fill='both', expand=True)
        btn_row = tk.Frame(rf, bg=C['panel']); btn_row.pack(fill='x', pady=(0,6))
        mbtn(btn_row,'🔍 Analyze Headers', self._run_email,
             color=C['accent'], width=22).pack(side='left', padx=(0,8))
        mbtn(btn_row,'🗑 Clear', lambda: [
             self._email_input.delete('1.0','end'),
             self._email_output.config(state='normal'),
             self._email_output.delete('1.0','end'),
             self._email_output.config(state='disabled')
        ], color=C['danger'], width=10).pack(side='left')
        tk.Label(rf, text='📊 Analysis Results:', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,4))
        self._email_output = mlog(rf); self._email_output.pack(fill='both', expand=True)

    # ═══════════════════════════════════════════════════════
    #  PAGE 7 — EVENT LOG
    # ═══════════════════════════════════════════════════════
    def _page_eventlog(self, parent):
        tk.Label(parent, text='Windows Event Log Parser', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Load a .evtx file OR scan live Windows Security logs.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        file_row(top, '.evtx File:', self.evtx_path, self._browse_evtx)
        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(6,0))
        mbtn(br,'📂 Parse .evtx',self._run_evtx,width=18).pack(side='left',padx=(0,8))
        mbtn(br,'🖥 Scan Live Logs',self._run_live_logs,color=C['warn'],width=18).pack(side='left')

        ff = tk.Frame(parent, bg=C['bg']); ff.pack(fill='x', pady=(0,6))
        self._evtl_filter = tk.StringVar()
        tk.Label(ff, text='Filter:', font=FBD, bg=C['bg'], fg=C['muted']).pack(side='left', padx=(0,4))
        fe = tk.Entry(ff, textvariable=self._evtl_filter, font=FM,
                      bg=C['panel'], fg=C['text'], insertbackground=C['text'],
                      relief='flat', bd=0, width=40,
                      highlightthickness=1, highlightbackground=C['border'])
        fe.pack(side='left', ipady=4)
        fe.bind('<KeyRelease>', lambda e: self._evtl_apply_filter())
        mbtn(ff,'⚠ Interesting Only',self._evtl_interesting,color=C['warn'],width=18).pack(side='left',padx=8)
        mbtn(ff,'↺ All',self._evtl_show_all,width=8).pack(side='left')

        f, self._evtl_tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._evtl_status = tk.Label(parent, text='No log loaded.',
                                     font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._evtl_status.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 8 — STEGANOGRAPHY
    # ═══════════════════════════════════════════════════════
    def _page_stego(self, parent):
        tk.Label(parent, text='Steganography Detector', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Detects hidden data via LSB analysis, chi-square test, and EOF byte check.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        file_row(top, 'Image File:', self.stego_path, self._browse_stego)
        mbtn(top,'🔑 Detect Hidden Data',self._run_stego,width=22).pack(anchor='w', pady=(6,0))

        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='Analysis Results', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._stego_text = mlog(res); self._stego_text.pack(fill='both', expand=True)
        self._stego_verdict = tk.Label(parent, text='', font=FH2, bg=C['bg'], anchor='w')
        self._stego_verdict.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 9 — USB
    # ═══════════════════════════════════════════════════════
    def _page_usb(self, parent):
        tk.Label(parent, text='USB Activity Monitor', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Scans Windows Registry / Linux syslog for USB device history.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        mbtn(top,'📱 Scan USB Devices',self._run_usb,width=22).pack(anchor='w')
        f, self._usb_tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._usb_status = tk.Label(parent, text='Not scanned yet.',
                                    font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._usb_status.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 10 — MEMORY DUMP
    # ═══════════════════════════════════════════════════════
    def _page_memory(self, parent):
        tk.Label(parent, text='Memory Dump Analyzer', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Extracts URLs, IPs, emails, processes, and malware strings from .dmp/.raw files.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        file_row(top, 'Dump File (.dmp/.raw):', self.dump_path, self._browse_dump)
        mbtn(top,'🧠 Analyze Dump',self._run_memory,width=18).pack(anchor='w', pady=(6,0))
        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='Extracted Artifacts', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._mem_text = mlog(res); self._mem_text.pack(fill='both', expand=True)

    # ═══════════════════════════════════════════════════════
    #  PAGE 11 — DELETED FILES
    # ═══════════════════════════════════════════════════════
    def _page_deleted(self, parent):
        tk.Label(parent, text='Deleted File Recovery', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Scans Recycle Bin, Temp folders, Trash, and can carve files from disk images.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._carve_img = tk.StringVar(); self._carve_out = tk.StringVar()
        file_row(top, 'Disk Image (carve):', self._carve_img, self._browse_carve_img)
        file_row(top, 'Carve Output Dir:',   self._carve_out, self._browse_carve_out)
        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(6,0))
        mbtn(br,'🗑 Scan Recycle/Temp/Trash',self._run_deleted_scan,width=26).pack(side='left',padx=(0,8))
        mbtn(br,'🔪 Carve Disk Image',self._run_carve,color=C['warn'],width=20).pack(side='left')
        f, self._del_tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._del_status = tk.Label(parent, text='Not scanned yet.',
                                    font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._del_status.pack(fill='x', pady=(4,0))

    # ═══════════════════════════════════════════════════════
    #  PAGE 12 — REPORT
    # ═══════════════════════════════════════════════════════
    def _page_report(self, parent):
        tk.Label(parent, text='Forensic Report Generator', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,8))
        c1 = mcard(parent, padx=12, pady=12); c1.pack(fill='x', pady=(0,8))
        self._report_title = tk.StringVar(value='Digital Forensic Investigation Report')
        self._report_out   = tk.StringVar(
            value=str(Path(__file__).parent.parent/'output'/'report.pdf'))
        file_row(c1, 'Report Title:', self._report_title, lambda: None)
        file_row(c1, 'Output PDF:',   self._report_out,   self._browse_report_out)

        tk.Label(c1, text='Include Sections:', font=FBD,
                 bg=C['panel'], fg=C['muted']).pack(anchor='w', pady=(8,4))
        self._inc = {}
        checks = [('timeline','Timeline'),('metadata','Metadata'),('hash','Hash'),
                  ('browser','Browser'),('email','Email'),('eventlog','Event Logs'),
                  ('stego','Stego'),('usb','USB'),('memory','Memory'),('deleted','Deleted')]
        cf = tk.Frame(c1, bg=C['panel']); cf.pack(fill='x')
        for i,(key,lbl) in enumerate(checks):
            v = tk.BooleanVar(value=True); self._inc[key] = v
            tk.Checkbutton(cf, text=lbl, variable=v, font=FB, bg=C['panel'],
                           fg=C['text'], selectcolor=C['bg'],
                           activebackground=C['panel']
                           ).grid(row=i//5, column=i%5, padx=4, pady=2, sticky='w')
        mbtn(c1,'📄 Generate PDF Report',self._generate_report,width=26).pack(anchor='w',pady=(10,0))

        self._report_preview = mlog(parent)
        self._report_preview.pack(fill='both', expand=True, pady=(8,0))
        mlog_write(self._report_preview, 'Configure options above and click Generate.')

    # ═══════════════════════════════════════════════════════
    #  Browse Helpers
    # ═══════════════════════════════════════════════════════
    def _browse_csv(self, switch=False):
        p = filedialog.askopenfilename(title='Select Autopsy CSV',
                                        filetypes=[('CSV','*.csv'),('All','*.*')])
        if p:
            self.csv_path.set(p)
            if switch: self._show_tab('timeline')
            self._log_write(f'CSV: {Path(p).name}')

    def _browse_file(self):
        p = filedialog.askopenfilename(title='Select File')
        if p: self.file_path.set(p)

    def _browse_hash_file(self):
        p = filedialog.askopenfilename(title='Select File')
        if p: self.hash_path.set(p)

    def _browse_evtx(self):
        p = filedialog.askopenfilename(title='Select .evtx',
                                        filetypes=[('Event Log','*.evtx'),('All','*.*')])
        if p: self.evtx_path.set(p)

    def _browse_stego(self):
        p = filedialog.askopenfilename(title='Select Image',
                                        filetypes=[('Images','*.jpg *.jpeg *.png *.bmp'),('All','*.*')])
        if p: self.stego_path.set(p)

    def _browse_dump(self):
        p = filedialog.askopenfilename(title='Select Memory Dump',
                                        filetypes=[('Dump','*.dmp *.raw *.mem *.bin'),('All','*.*')])
        if p: self.dump_path.set(p)

    def _browse_carve_img(self):
        p = filedialog.askopenfilename(title='Select Disk Image')
        if p: self._carve_img.set(p)

    def _browse_carve_out(self):
        p = filedialog.askdirectory(title='Select Output Directory')
        if p: self._carve_out.set(p)

    def _browse_report_out(self):
        p = filedialog.asksaveasfilename(title='Save Report As',
                                          defaultextension='.pdf',
                                          filetypes=[('PDF','*.pdf')])
        if p: self._report_out.set(p)

    # ═══════════════════════════════════════════════════════
    #  Timeline Logic
    # ═══════════════════════════════════════════════════════
    def _run_analysis(self):
        p = self.csv_path.get().strip()
        if not p: messagebox.showwarning('No CSV','Please select an Autopsy CSV.'); return
        threading.Thread(target=self._do_analysis, daemon=True).start()

    def _do_analysis(self):
        az = TimelineAnalyzer(self.csv_path.get().strip())
        if not az.load():
            self.after(0, lambda: messagebox.showerror('Error','Failed to load CSV.')); return
        stats = az.analyse()
        self._analyzer = az; self._timeline = az.build_timeline()
        self.after(0, lambda: self._pop_tree(self._tree, self._timeline,
                                              az.suspicious, az.anomalies))
        self.after(0, lambda: [
            self._stat_cards['total_records'].config(text=str(stats.get('total_records','—'))),
            self._stat_cards['suspicious_files'].config(text=str(stats.get('suspicious_files','—'))),
            self._stat_cards['anomalies'].config(text=str(stats.get('anomalies','—'))),
        ])
        self.after(0, lambda: self._log_write(
            f'CSV: {stats["total_records"]} records, {stats["suspicious_files"]} suspicious.'))

    def _pop_tree(self, tv, records, suspicious=None, anomalies=None):
        if not records: return
        sus_ids = {id(r) for r in (suspicious or [])}
        ano_ids = {id(r) for r in (anomalies  or [])}
        cols = [c for c in records[0].keys() if not c.startswith('_')]
        tv.config(columns=cols)
        for c in cols: tv.heading(c,text=c); tv.column(c,width=120,minwidth=50)
        for row in tv.get_children(): tv.delete(row)
        for rec in records:
            vals=[rec.get(c,'') for c in cols]
            tag='red' if id(rec) in sus_ids else ('warn' if id(rec) in ano_ids else '')
            tv.insert('','end',values=vals,tags=(tag,) if tag else ())
        self._tl_status.config(text=f'Showing {len(records)} records.')

    def _apply_filter(self):
        if not self._analyzer: return
        q = self._filter_var.get().lower()
        filtered = [r for r in self._timeline if q in ' '.join(str(v) for v in r.values()).lower()]
        self._pop_tree(self._tree, filtered)

    def _show_suspicious(self):
        if not self._analyzer: return
        self._pop_tree(self._tree, self._analyzer.suspicious)
        self._tl_status.config(text=f'{len(self._analyzer.suspicious)} suspicious files.')

    def _show_all(self):
        if not self._analyzer: return
        self._pop_tree(self._tree, self._timeline, self._analyzer.suspicious, self._analyzer.anomalies)

    # ═══════════════════════════════════════════════════════
    #  Metadata Logic
    # ═══════════════════════════════════════════════════════
    def _run_metadata(self):
        p = self.file_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select a file.'); return
        threading.Thread(target=self._do_metadata, daemon=True).start()

    def _do_metadata(self):
        info = FileMetadataExtractor().extract(self.file_path.get().strip())
        self._meta_result = info
        self.after(0, lambda: self._display_metadata(info))

    def _display_metadata(self, info):
        skip = {'exif','warnings'}
        lines = [f'{k:<22}: {v}' for k,v in info.items() if k not in skip]
        if info.get('warnings'): lines += ['','─── WARNINGS ───────────────────']+info['warnings']
        self._meta_text.config(state='normal'); self._meta_text.delete('1.0','end')
        self._meta_text.insert('end','\n'.join(lines)); self._meta_text.config(state='disabled')

        exif = info.get('exif',{})
        lines2 = ['No EXIF data available.'] if not exif else []
        for k,v in exif.items():
            if isinstance(v,dict):
                lines2.append(f'\n[{k}]')
                for gk,gv in v.items(): lines2.append(f'  {gk:<22}: {gv}')
            else: lines2.append(f'{k:<26}: {v}')
        self._exif_text.config(state='normal'); self._exif_text.delete('1.0','end')
        self._exif_text.insert('end','\n'.join(lines2)); self._exif_text.config(state='disabled')

        warns = info.get('warnings',[])
        self._meta_warn.config(text='  '.join(warns) if warns else '✅ No warnings — file appears clean.')
        self._log_write(f'Metadata: {info["file_name"]}')

    # ═══════════════════════════════════════════════════════
    #  Hash Logic
    # ═══════════════════════════════════════════════════════
    def _run_hash_compute(self):
        p = self.hash_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select a file.'); return
        threading.Thread(target=lambda: self.after(0,
            lambda: self._display_hash(HashVerifier.compute(p))), daemon=True).start()

    def _display_hash(self, result):
        self._hash_text.config(state='normal'); self._hash_text.delete('1.0','end')
        for k,v in result.items(): self._hash_text.insert('end',f'{k:<10}: {v}\n')
        self._hash_text.config(state='disabled')
        self._log_write('Hash computation complete.')

    def _run_hash_verify(self):
        p,exp,alg = self.hash_path.get().strip(),self.hash_expected.get().strip(),self.hash_algo.get()
        if not p or not exp: messagebox.showwarning('Missing','Select file and enter expected hash.'); return
        threading.Thread(target=lambda: self.after(0,
            lambda: self._show_verify_result(HashVerifier.verify(p,exp,alg))), daemon=True).start()

    def _show_verify_result(self, result):
        self._hash_text.config(state='normal'); self._hash_text.delete('1.0','end')
        for k,v in result.items(): self._hash_text.insert('end',f'{k:<12}: {v}\n')
        self._hash_text.config(state='disabled')
        if result.get('match'):
            self._hash_result_lbl.config(text='✅ MATCH — File integrity verified.',fg=C['success'])
            self._log_write('Hash: MATCH ✅')
        else:
            self._hash_result_lbl.config(text='❌ MISMATCH — File may be tampered!',fg=C['danger'])
            self._log_write('Hash: MISMATCH ❌')

    # ═══════════════════════════════════════════════════════
    #  Browser Logic
    # ═══════════════════════════════════════════════════════
    def _run_browser(self):
        self._browser_status.config(text='Scanning browsers…')
        threading.Thread(target=self._do_browser, daemon=True).start()

    def _do_browser(self):
        az = BrowserHistoryAnalyzer()
        result = az.analyse(); self._browser_result = result
        self.after(0, lambda: self._display_browser(result, az.summary()))

    def _display_browser(self, result, summary):
        def fill(widget, rows, keys):
            widget.config(state='normal'); widget.delete('1.0','end')
            if not rows: widget.insert('end','No data found.')
            else:
                for r in rows:
                    widget.insert('end','  |  '.join(str(r.get(k,'')) for k in keys)+'\n')
            widget.config(state='disabled')

        fill(self._brow_tabs['chrome_history'],   result['chrome']['history'],   ['last_visit','title','url','visit_count'])
        fill(self._brow_tabs['chrome_downloads'], result['chrome']['downloads'], ['time','path','url'])
        fill(self._brow_tabs['chrome_searches'],  result['chrome']['searches'],  ['term'])
        fill(self._brow_tabs['edge_history'],     result['edge']['history'],     ['last_visit','title','url'])
        fill(self._brow_tabs['edge_downloads'],   result['edge']['downloads'],   ['time','path','url'])
        fill(self._brow_tabs['firefox_history'],  result['firefox']['history'],  ['last_visit','title','url'])
        fill(self._brow_tabs['firefox_downloads'],result['firefox']['downloads'],['time','url'])
        self._browser_status.config(
            text=f"Chrome: {summary['chrome_history']} URLs  |  Edge: {summary['edge_history']}  |  Firefox: {summary['firefox_history']}")
        self._log_write(f"Browser scan: Chrome {summary['chrome_history']}, Firefox {summary['firefox_history']} records.")

    # ═══════════════════════════════════════════════════════
    #  Email Logic
    # ═══════════════════════════════════════════════════════
    def _run_email(self):
        raw = self._email_input.get('1.0','end').strip()
        if not raw: messagebox.showwarning('Empty','Paste raw email headers first.'); return
        threading.Thread(target=self._do_email, args=(raw,), daemon=True).start()

    def _do_email(self, raw):
        result = EmailHeaderAnalyzer(raw).analyse()
        self._email_result = result
        self.after(0, lambda: self._display_email(result))

    def _display_email(self, result):
        self._email_output.config(state='normal'); self._email_output.delete('1.0','end')
        for k,v in result.items():
            if k in ('warnings','received_chain','public_ips'): continue
            self._email_output.insert('end',f'{k:<22}: {v}\n')
        self._email_output.insert('end','\n─── Public IPs Traced ─────────────────\n')
        for ip in result.get('public_ips',[]): self._email_output.insert('end',f'  {ip}\n')
        self._email_output.insert('end','\n─── Received Hop Chain ────────────────\n')
        for i,hop in enumerate(result.get('received_chain',[])):
            self._email_output.insert('end',f'Hop {i+1}: {hop[:120]}\n')
        self._email_output.insert('end','\n─── Security Warnings ─────────────────\n')
        for w in result.get('warnings',[]): self._email_output.insert('end',f'{w}\n')
        self._email_output.config(state='disabled')
        self._log_write(f"Email analyzed: {result.get('from','?')}")

    # ═══════════════════════════════════════════════════════
    #  Event Log Logic
    # ═══════════════════════════════════════════════════════
    def _run_evtx(self):
        p = self.evtx_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select a .evtx file.'); return
        threading.Thread(target=self._do_evtx, daemon=True).start()

    def _do_evtx(self):
        parser = WindowsEventLogParser()
        events = parser.parse_evtx(self.evtx_path.get().strip())
        self._evtlog_result = events; self._evtlog_parser = parser
        self.after(0, lambda: self._display_events(events, parser.summary()))

    def _run_live_logs(self):
        threading.Thread(target=self._do_live_logs, daemon=True).start()

    def _do_live_logs(self):
        parser = WindowsEventLogParser()
        events = parser.read_live()
        self._evtlog_result = events; self._evtlog_parser = parser
        self.after(0, lambda: self._display_events(events, parser.summary()))

    def _display_events(self, events, summary):
        tv = self._evtl_tree
        cols = ['event_id','label','time','computer','TargetUserName','IpAddress','ProcessName']
        tv.config(columns=cols)
        for c in cols: tv.heading(c,text=c); tv.column(c,width=130,minwidth=60)
        for row in tv.get_children(): tv.delete(row)
        for e in events:
            vals=[str(e.get(c,'')) for c in cols]
            tag='red' if e.get('interesting') else ''
            tv.insert('','end',values=vals,tags=(tag,) if tag else ())
        self._evtl_status.config(
            text=f"Total: {summary['total_events']}  |  Flagged: {summary['interesting_events']}")
        self._log_write(f"Event log: {summary['total_events']} events, {summary['interesting_events']} flagged.")

    def _evtl_apply_filter(self):
        if not self._evtlog_result: return
        q = self._evtl_filter.get().lower()
        filtered = [e for e in self._evtlog_result
                    if q in ' '.join(str(v) for v in e.values()).lower()]
        self._display_events(filtered,{'total_events':len(filtered),'interesting_events':0,'errors':[]})

    def _evtl_interesting(self):
        if not self._evtlog_parser: return
        ev = self._evtlog_parser.interesting_only()
        self._display_events(ev,{'total_events':len(ev),'interesting_events':len(ev),'errors':[]})

    def _evtl_show_all(self):
        if self._evtlog_result:
            self._display_events(self._evtlog_result,
                                  (self._evtlog_parser or WindowsEventLogParser()).summary())

    # ═══════════════════════════════════════════════════════
    #  Steganography Logic
    # ═══════════════════════════════════════════════════════
    def _run_stego(self):
        p = self.stego_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select an image.'); return
        threading.Thread(target=self._do_stego, daemon=True).start()

    def _do_stego(self):
        result = SteganographyDetector(self.stego_path.get().strip()).analyse()
        self._stego_result = result
        self.after(0, lambda: self._display_stego(result))

    def _display_stego(self, r):
        self._stego_text.config(state='normal'); self._stego_text.delete('1.0','end')
        for k,v in r.items():
            if k == 'warnings': continue
            self._stego_text.insert('end',f'{k:<22}: {v}\n')
        self._stego_text.insert('end','\n─── Analysis Findings ─────────────────\n')
        for w in r.get('warnings',[]): self._stego_text.insert('end',f'{w}\n')
        self._stego_text.config(state='disabled')
        verdict = r.get('verdict','')
        col = C['danger'] if 'SUSPICIOUS' in verdict else (C['warn'] if 'Possibly' in verdict else C['success'])
        self._stego_verdict.config(text=f'Verdict: {verdict}', fg=col)
        self._log_write(f'Stego: {verdict}')

    # ═══════════════════════════════════════════════════════
    #  USB Logic
    # ═══════════════════════════════════════════════════════
    def _run_usb(self):
        threading.Thread(target=self._do_usb, daemon=True).start()

    def _do_usb(self):
        mon = USBActivityMonitor()
        devices = mon.scan(); self._usb_result = mon.summary()
        self.after(0, lambda: self._display_usb(devices, mon.summary()))

    def _display_usb(self, devices, summary):
        tv = self._usb_tree
        if not devices:
            cols=['source','message']; tv.config(columns=cols)
            for c in cols: tv.heading(c,text=c); tv.column(c,width=400)
            for row in tv.get_children(): tv.delete(row)
            msg = summary['errors'][0] if summary['errors'] else 'No USB devices found on this system.'
            tv.insert('','end',values=['System', msg])
        else:
            cols=list(devices[0].keys()); tv.config(columns=cols)
            for c in cols: tv.heading(c,text=c); tv.column(c,width=160,minwidth=60)
            for row in tv.get_children(): tv.delete(row)
            for d in devices: tv.insert('','end',values=[str(d.get(c,'')) for c in cols])
        self._usb_status.config(text=f"Found {summary['total_devices']} USB device record(s).")
        self._log_write(f"USB scan: {summary['total_devices']} device(s).")

    # ═══════════════════════════════════════════════════════
    #  Memory Logic
    # ═══════════════════════════════════════════════════════
    def _run_memory(self):
        p = self.dump_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select a memory dump.'); return
        threading.Thread(target=self._do_memory, daemon=True).start()

    def _do_memory(self):
        result = MemoryDumpAnalyzer(self.dump_path.get().strip()).analyse()
        self._mem_result = result
        self.after(0, lambda: self._display_memory(result))

    def _display_memory(self, r):
        self._mem_text.config(state='normal'); self._mem_text.delete('1.0','end')
        self._mem_text.insert('end',f'File: {r["file"]}  |  Size: {r["size_human"]}\n\n')
        self._mem_text.insert('end','─── Suspicious Strings ─────────────────\n')
        for s in r['suspicious_strings']: self._mem_text.insert('end',f'  ⚠ {s}\n')
        self._mem_text.insert('end',f'\n─── Processes Found ────────────────────\n')
        for p in r['processes_found']: self._mem_text.insert('end',f'  {p}\n')
        self._mem_text.insert('end',f'\n─── URLs ({len(r["urls"])}) ────────────────────────\n')
        for u in r['urls'][:50]: self._mem_text.insert('end',f'  {u}\n')
        self._mem_text.insert('end',f'\n─── IPs ({len(r["ips"])}) ─────────────────────────\n')
        for ip in r['ips'][:50]: self._mem_text.insert('end',f'  {ip}\n')
        self._mem_text.insert('end',f'\n─── Emails ({len(r["emails"])}) ──────────────────────\n')
        for em in r['emails'][:30]: self._mem_text.insert('end',f'  {em}\n')
        self._mem_text.insert('end','\n─── Warnings ───────────────────────────\n')
        for w in r['warnings']: self._mem_text.insert('end',f'{w}\n')
        self._mem_text.config(state='disabled')
        self._log_write(f"Memory: {len(r['urls'])} URLs, {len(r['ips'])} IPs, {len(r['suspicious_strings'])} suspicious.")

    # ═══════════════════════════════════════════════════════
    #  Deleted Logic
    # ═══════════════════════════════════════════════════════
    def _run_deleted_scan(self):
        threading.Thread(target=self._do_deleted_scan, daemon=True).start()

    def _do_deleted_scan(self):
        scanner = DeletedFileScanner()
        items = scanner.scan_all(); self._del_result = scanner.summary()
        self.after(0, lambda: self._display_deleted(items))

    def _run_carve(self):
        img = self._carve_img.get().strip(); out = self._carve_out.get().strip()
        if not img or not out:
            messagebox.showwarning('Missing','Select disk image and output directory.'); return
        threading.Thread(target=lambda: self.after(0,
            lambda: self._display_deleted(DeletedFileScanner().carve_image(img, out))),
            daemon=True).start()

    def _display_deleted(self, items):
        tv = self._del_tree
        if not items:
            cols=['message']; tv.config(columns=cols)
            tv.heading('message',text='Result'); tv.column('message',width=700)
            for row in tv.get_children(): tv.delete(row)
            tv.insert('','end',values=['No deleted file artifacts found on this system.'])
        else:
            cols=list(items[0].keys()); tv.config(columns=cols)
            for c in cols: tv.heading(c,text=c); tv.column(c,width=160,minwidth=60)
            for row in tv.get_children(): tv.delete(row)
            for it in items: tv.insert('','end',values=[str(it.get(c,'')) for c in cols])
        self._del_status.config(text=f'Found {len(items)} artifact(s).')
        self._log_write(f'Deleted scan: {len(items)} artifacts.')

    # ═══════════════════════════════════════════════════════
    #  Report Logic
    # ═══════════════════════════════════════════════════════
    def _generate_report(self):
        out = self._report_out.get().strip()
        if not out: messagebox.showwarning('No Path','Specify output PDF path.'); return
        os.makedirs(Path(out).parent, exist_ok=True)
        threading.Thread(target=self._do_generate_report, daemon=True).start()

    def _do_generate_report(self):
        self.after(0, lambda: mlog_write(self._report_preview, 'Building report…'))
        builder = ForensicReportBuilder(self._report_out.get().strip())
        builder.set_meta(self._report_title.get(),
                         self.investigator.get() or 'N/A',
                         self.case_id.get() or 'N/A')

        if self._inc['timeline'].get() and self._analyzer:
            s = self._analyzer.stats
            # Only summary stats — no full table (keeps report concise)
            sus_list = self._analyzer.suspicious[:20]
            ano_list = self._analyzer.anomalies[:20]
            lines = [
                f'CSV File         : {s.get("csv_path","")}',
                f'Total Records    : {s.get("total_records",0)}',
                f'Suspicious Files : {s.get("suspicious_files",0)}',
                f'Anomalies Found  : {s.get("anomalies",0)}',
                f'Columns          : {", ".join(s.get("columns",[]))}',
                '',
                '─── Top Suspicious Files ───────────────',
            ]
            if sus_list:
                for item in sus_list:
                    name = (item.get('Name') or item.get('File Name') or
                            item.get('name') or '[unknown]')
                    lines.append(f'  ⚠ {name}  —  {item.get("_reason","")}')
            else:
                lines.append('  None detected.')
            lines += ['', '─── Top Anomalies ──────────────────────']
            if ano_list:
                for item in ano_list:
                    name = (item.get('Name') or item.get('File Name') or
                            item.get('name') or '[unknown]')
                    lines.append(f'  ⚡ {name}  —  {item.get("_reason","")}')
            else:
                lines.append('  None detected.')
            builder.add_section('1. Timeline Analysis Summary', lines)
            # Do NOT call set_timeline_records — keeps report short

        if self._inc['metadata'].get() and self._meta_result:
            m = self._meta_result
            lines = [f'{k:<20}: {v}' for k,v in m.items() if k not in ('exif','warnings')]
            exif = m.get('exif',{})
            if exif and 'error' not in exif:
                lines += ['','EXIF Data:']
                for k,v in exif.items():
                    lines.append(f'  {k}: {str(v)[:150]}' if not isinstance(v,dict)
                                 else f'  [{k}]: {json.dumps(v)[:150]}')
            lines += [f'⚠ {w}' for w in m.get('warnings',[])]
            builder.add_section('2. File Metadata Analysis', lines)

        if self._inc['hash'].get():
            raw = self._hash_text.get('1.0','end').strip()
            if raw: builder.add_section('3. Hash Verification', raw.splitlines())

        if self._inc['browser'].get() and self._browser_result:
            lines = []
            for browser, data in self._browser_result.items():
                h=data.get('history',[]); d=data.get('downloads',[])
                lines.append(f'{browser.title()}: {len(h)} URLs, {len(d)} downloads')
                for rec in h[:10]:
                    lines.append(f'  {rec.get("last_visit","?")}  {rec.get("url","")[:80]}')
            builder.add_section('4. Browser History & Cache', lines)

        if self._inc['email'].get() and self._email_result:
            r = self._email_result
            lines=[f'{k:<22}: {v}' for k,v in r.items()
                   if k not in ('warnings','received_chain','public_ips')]
            lines += ['','Public IPs:']+[f'  {ip}' for ip in r.get('public_ips',[])]
            lines += ['','Warnings:']+r.get('warnings',[])
            builder.add_section('5. Email Header Analysis', lines)

        if self._inc['eventlog'].get() and self._evtlog_result:
            interesting=[e for e in self._evtlog_result if e.get('interesting')]
            lines=[f'Total Events: {len(self._evtlog_result)}',
                   f'Flagged: {len(interesting)}','']
            for e in interesting[:30]:
                lines.append(f'{e.get("time","?")}  [{e.get("event_id","")}] {e.get("label","")}')
            builder.add_section('6. Windows Event Log Analysis', lines)

        if self._inc['stego'].get() and self._stego_result:
            r = self._stego_result
            lines=[f'{k:<22}: {v}' for k,v in r.items() if k!='warnings']
            lines += ['']+r.get('warnings',[])
            builder.add_section('7. Steganography Analysis', lines)

        if self._inc['usb'].get() and self._usb_result:
            r = self._usb_result
            lines=[f'Total USB Devices: {r.get("total_devices",0)}','']
            for d in r.get('devices',[])[:30]:
                lines.append('  |  '.join(f'{k}: {v}' for k,v in d.items()))
            builder.add_section('8. USB Device Activity', lines)

        if self._inc['memory'].get() and self._mem_result:
            r = self._mem_result
            lines=[f'File: {r.get("file","")}  |  Size: {r.get("size_human","")}',
                   f'URLs: {len(r.get("urls",[]))}  IPs: {len(r.get("ips",[]))}  Emails: {len(r.get("emails",[]))}',
                   f'Processes: {", ".join(r.get("processes_found",[]))}',
                   f'Suspicious: {", ".join(r.get("suspicious_strings",[]))}',
                   ]+r.get('warnings',[])
            builder.add_section('9. Memory Dump Analysis', lines)

        if self._inc['deleted'].get() and self._del_result:
            r = self._del_result
            lines=[f'Total Artifacts: {r.get("total_artifacts",0)}','']
            for a in r.get('artifacts',[])[:30]:
                lines.append(f'{a.get("source","?")}  |  {a.get("name","?")}  |  {a.get("size_human","?")}')
            builder.add_section('10. Deleted File Recovery', lines)

        ok = builder.build()
        out = self._report_out.get()
        if ok:
            self.after(0, lambda: mlog_write(self._report_preview, f'✅ Report saved: {out}'))
            self.after(0, lambda: self._log_write(f'PDF report: {Path(out).name}'))
            self.after(0, lambda: messagebox.showinfo('Done', f'Report saved:\n{out}'))
        else:
            self.after(0, lambda: mlog_write(self._report_preview, '❌ Failed to generate PDF.'))



    # ═══════════════════════════════════════════════════════
    #  PAGE 13 — PASSWORD STRENGTH CHECKER
    # ═══════════════════════════════════════════════════════
    def _page_password(self, parent):
        tk.Label(parent, text='Password Strength Checker', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Forensic analysis: entropy, crack time, pattern detection.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))

        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._pwd_var = tk.StringVar()
        self._pwd_show = tk.BooleanVar(value=False)

        rf = tk.Frame(top, bg=C['panel']); rf.pack(fill='x', pady=3)
        tk.Label(rf, text='Password:', font=FBD, bg=C['panel'],
                 fg=C['muted'], width=14, anchor='w').pack(side='left')
        self._pwd_entry = tk.Entry(rf, textvariable=self._pwd_var, font=FM,
                 bg=C['bg'], fg=C['text'], insertbackground=C['text'],
                 relief='flat', bd=0, width=50, show='●',
                 highlightthickness=1, highlightbackground=C['border'])
        self._pwd_entry.pack(side='left', padx=6, ipady=5)
        self._pwd_entry.bind('<KeyRelease>', lambda e: self._run_password_live())

        tk.Checkbutton(rf, text='Show', variable=self._pwd_show, font=FB,
                       bg=C['panel'], fg=C['muted'], selectcolor=C['bg'],
                       activebackground=C['panel'],
                       command=self._toggle_pwd_show).pack(side='left', padx=6)
        mbtn(top, '🔐 Analyze', self._run_password, width=14).pack(anchor='w', pady=(6,0))

        # Score bar
        bar_f = tk.Frame(parent, bg=C['bg']); bar_f.pack(fill='x', pady=(0,8))
        tk.Label(bar_f, text='Strength:', font=FBD, bg=C['bg'],
                 fg=C['muted']).pack(side='left', padx=(0,8))
        self._pwd_bar_canvas = tk.Canvas(bar_f, height=22, bg=C['panel'],
                                          highlightthickness=0, width=400)
        self._pwd_bar_canvas.pack(side='left')
        self._pwd_score_lbl = tk.Label(bar_f, text='', font=FBD,
                                        bg=C['bg'], fg=C['text'])
        self._pwd_score_lbl.pack(side='left', padx=8)

        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='Analysis Results', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._pwd_text = mlog(res); self._pwd_text.pack(fill='both', expand=True)

    def _toggle_pwd_show(self):
        self._pwd_entry.config(show='' if self._pwd_show.get() else '●')

    def _run_password_live(self):
        pw = self._pwd_var.get()
        if not pw:
            self._pwd_bar_canvas.delete('all')
            self._pwd_score_lbl.config(text='')
            return
        r = PasswordStrengthChecker().analyse(pw)
        score = r['score']
        color = (C['danger'] if score < 30 else C['warn'] if score < 60
                 else C['success'] if score < 80 else '#58a6ff')
        w = int(400 * score / 100)
        self._pwd_bar_canvas.delete('all')
        self._pwd_bar_canvas.create_rectangle(0,0,400,22, fill=C['panel'], outline='')
        self._pwd_bar_canvas.create_rectangle(0,0,w,22, fill=color, outline='')
        self._pwd_score_lbl.config(text=f"{score}/100 — {r['strength_label']}", fg=color)

    def _run_password(self):
        pw = self._pwd_var.get()
        if not pw: messagebox.showwarning('Empty','Enter a password to analyse.'); return
        r = PasswordStrengthChecker().analyse(pw)
        self._pwd_text.config(state='normal'); self._pwd_text.delete('1.0','end')
        self._pwd_text.insert('end', f'{"Strength":<22}: {r["strength_label"]}\n')
        self._pwd_text.insert('end', f'{"Score":<22}: {r["score"]}/100\n')
        self._pwd_text.insert('end', f'{"Length":<22}: {r["length"]} characters\n')
        self._pwd_text.insert('end', f'{"Entropy":<22}: {r["entropy_bits"]} bits\n')
        self._pwd_text.insert('end', f'{"Crack Time (GPU)":<22}: {r["crack_time"]}\n')
        self._pwd_text.insert('end', f'{"Has Uppercase":<22}: {r["has_upper"]}\n')
        self._pwd_text.insert('end', f'{"Has Lowercase":<22}: {r["has_lower"]}\n')
        self._pwd_text.insert('end', f'{"Has Digits":<22}: {r["has_digit"]}\n')
        self._pwd_text.insert('end', f'{"Has Special Chars":<22}: {r["has_special"]}\n')
        self._pwd_text.insert('end', f'{"Is Common Password":<22}: {r["is_common"]}\n')
        self._pwd_text.insert('end', f'{"Keyboard Walk":<22}: {r["has_keyboard_walk"]}\n')
        self._pwd_text.insert('end', f'{"Date Pattern":<22}: {r["has_date_pattern"]}\n')
        self._pwd_text.insert('end', f'{"Repeated Chars":<22}: {r["has_repeated"]}\n')
        if r["warnings"]:
            self._pwd_text.insert('end', '\n─── Warnings ─────────────────────────\n')
            for w in r["warnings"]: self._pwd_text.insert('end', f'{w}\n')
        if r["suggestions"]:
            self._pwd_text.insert('end', '\n─── Suggestions ───────────────────────\n')
            for s in r["suggestions"]: self._pwd_text.insert('end', f'  • {s}\n')
        self._pwd_text.config(state='disabled')
        self._last_pwd_result = {k: str(v) for k, v in r.items() if k != 'suggestions'}
        self._log_write(f'Password checked: {r["strength_label"]} ({r["score"]}/100)')

    # ═══════════════════════════════════════════════════════
    #  PAGE 14 — NETWORK PACKET ANALYZER
    # ═══════════════════════════════════════════════════════
    def _page_network(self, parent):
        tk.Label(parent, text='Network Packet Analyzer', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Load a .pcap file — extracts IPs, ports, protocols, suspicious connections.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._pcap_path = tk.StringVar()
        file_row(top, '.pcap File:', self._pcap_path,
                 lambda: self._pcap_path.set(
                     filedialog.askopenfilename(title='Select PCAP',
                         filetypes=[('PCAP','*.pcap *.pcapng'),('All','*.*')]) or self._pcap_path.get()))
        mbtn(top,'📡 Analyze Packets', self._run_network, width=20).pack(anchor='w', pady=(6,0))

        nb = ttk.Notebook(parent); nb.pack(fill='both', expand=True)
        for label in ('Connections','Suspicious','Top Talkers','Protocols','Summary'):
            f = tk.Frame(nb, bg=C['panel']); nb.add(f, text=label)
            t = mlog(f); t.pack(fill='both', expand=True, padx=4, pady=4)
            setattr(self, f'_net_{label.lower().replace(" ","_")}', t)

        self._net_status = tk.Label(parent, text='No PCAP loaded.',
                                    font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._net_status.pack(fill='x', pady=(4,0))

    def _run_network(self):
        p = self._pcap_path.get().strip()
        if not p: messagebox.showwarning('No File','Please select a .pcap file.'); return
        threading.Thread(target=self._do_network, daemon=True).start()

    def _do_network(self):
        r = NetworkPacketAnalyzer(self._pcap_path.get().strip()).analyse()
        self.after(0, lambda: self._display_network(r))

    def _display_network(self, r):
        def fill(attr, lines):
            t = getattr(self, attr)
            t.config(state='normal'); t.delete('1.0','end')
            t.insert('end', lines); t.config(state='disabled')

        fill('_net_connections',  '\n'.join(r['connections'][:200]) or 'None found.')
        fill('_net_suspicious',   '\n'.join(r['suspicious'])        or '✅ No suspicious ports detected.')
        fill('_net_top_talkers',  '\n'.join(f'{ip:<20}: {cnt} packets'
             for ip,cnt in r['top_talkers'].items()) or 'None.')
        fill('_net_protocols',    '\n'.join(f'{p:<10}: {c}' for p,c in r['protocols'].items()) or 'None.')
        fill('_net_summary',      '\n'.join([
            f'File          : {r["file"]}',
            f'Total Packets : {r["total_packets"]}',
            f'Connections   : {len(r["connections"])}',
            f'Suspicious    : {len(r["suspicious"])}',
            f'Top Talkers   : {len(r["top_talkers"])}',
            f'Protocols     : {", ".join(r["protocols"].keys())}',
            '', '─── Warnings ───────────────────────────'
        ] + r['warnings']))
        self._net_status.config(
            text=f'Packets: {r["total_packets"]}  |  Suspicious: {len(r["suspicious"])}  |  Connections: {len(r["connections"])}')
        self._log_write(f'PCAP: {r["total_packets"]} packets, {len(r["suspicious"])} suspicious.')

    # ═══════════════════════════════════════════════════════
    #  PAGE 15 — FILE INTEGRITY MONITOR
    # ═══════════════════════════════════════════════════════
    def _page_integrity(self, parent):
        tk.Label(parent, text='File Integrity Monitor', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Take a baseline snapshot, then scan later to detect any file additions, deletions, or modifications.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._fim_folder   = tk.StringVar()
        self._fim_baseline = tk.StringVar(value=str(Path(__file__).parent.parent/'output'/'baseline.json'))
        file_row(top, 'Monitor Folder:', self._fim_folder,
                 lambda: self._fim_folder.set(filedialog.askdirectory() or self._fim_folder.get()))
        file_row(top, 'Baseline File:', self._fim_baseline,
                 lambda: self._fim_baseline.set(
                     filedialog.asksaveasfilename(defaultextension='.json',
                         filetypes=[('JSON','*.json')]) or self._fim_baseline.get()))
        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(6,0))
        mbtn(br,'📸 Save Baseline', self._run_fim_baseline, width=18).pack(side='left',padx=(0,8))
        mbtn(br,'🔍 Scan for Changes', self._run_fim_scan, color=C['warn'], width=20).pack(side='left')

        f, self._fim_tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._fim_status = tk.Label(parent, text='No scan performed yet.',
                                    font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._fim_status.pack(fill='x', pady=(4,0))

    def _run_fim_baseline(self):
        folder = self._fim_folder.get().strip()
        if not folder: messagebox.showwarning('No Folder','Select a folder to monitor.'); return
        threading.Thread(target=self._do_fim_baseline, daemon=True).start()

    def _do_fim_baseline(self):
        fim = FileIntegrityMonitor(self._fim_folder.get(), self._fim_baseline.get())
        result = fim.save_baseline()
        self.after(0, lambda: [
            self._fim_status.config(text=f'✅ Baseline saved: {result["saved"]} files → {result["path"]}'),
            self._log_write(f'Baseline saved: {result["saved"]} files.')])

    def _run_fim_scan(self):
        folder = self._fim_folder.get().strip()
        if not folder: messagebox.showwarning('No Folder','Select a folder first.'); return
        threading.Thread(target=self._do_fim_scan, daemon=True).start()

    def _do_fim_scan(self):
        fim = FileIntegrityMonitor(self._fim_folder.get(), self._fim_baseline.get())
        if not fim.load_baseline():
            self.after(0, lambda: messagebox.showwarning('No Baseline','Save a baseline first.')); return
        changes = fim.scan(); summary = fim.summary()
        self.after(0, lambda: self._display_fim(changes, summary))

    def _display_fim(self, changes, summary):
        tv = self._fim_tree
        cols = ['type','file','detail']
        tv.config(columns=cols)
        for c in cols: tv.heading(c,text=c.title()); tv.column(c,width=250,minwidth=80)
        for row in tv.get_children(): tv.delete(row)
        for ch in changes:
            tag = 'red' if ch['type']=='DELETED' else ('warn' if ch['type']=='MODIFIED' else '')
            tv.insert('','end', values=[ch['type'],ch['file'],ch['detail']],
                      tags=(tag,) if tag else ())
        self._fim_status.config(
            text=f"Changes: {summary['total_changes']}  |  "
                 f"Added: {summary['added']}  Deleted: {summary['deleted']}  Modified: {summary['modified']}")
        self._log_write(f"FIM scan: {summary['total_changes']} changes detected.")

    # ═══════════════════════════════════════════════════════
    #  PAGE 16 — MALWARE HASH LOOKUP (VirusTotal)
    # ═══════════════════════════════════════════════════════
    def _page_vtlookup(self, parent):
        tk.Label(parent, text='Malware Hash Lookup (VirusTotal)', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Check any file or hash against VirusTotal — requires a free API key from virustotal.com',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._vt_apikey = tk.StringVar()
        self._vt_hash   = tk.StringVar()
        self._vt_file   = tk.StringVar()

        def erow(label, var, browse=None):
            f = tk.Frame(top, bg=C['panel']); f.pack(fill='x', pady=3)
            tk.Label(f, text=label, font=FBD, bg=C['panel'],
                     fg=C['muted'], width=18, anchor='w').pack(side='left')
            tk.Entry(f, textvariable=var, font=FM, bg=C['bg'], fg=C['text'],
                     insertbackground=C['text'], relief='flat', bd=0, width=52,
                     highlightthickness=1, highlightbackground=C['border'],
                     show='●' if 'API' in label else ''
                     ).pack(side='left', padx=6, ipady=4)
            if browse: mbtn(f,'📂 Browse', browse, width=10).pack(side='left')

        erow('VT API Key:', self._vt_apikey)
        erow('Hash (MD5/SHA256):', self._vt_hash)
        erow('OR File Path:', self._vt_file,
             lambda: self._vt_file.set(filedialog.askopenfilename() or self._vt_file.get()))

        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(6,0))
        mbtn(br,'🦠 Lookup Hash', self._run_vtlookup_hash, width=18).pack(side='left',padx=(0,8))
        mbtn(br,'📂 Lookup File', self._run_vtlookup_file, color=C['warn'], width=18).pack(side='left')

        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='VirusTotal Results', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._vt_text = mlog(res); self._vt_text.pack(fill='both', expand=True)
        self._vt_verdict = tk.Label(parent, text='', font=FH2, bg=C['bg'], anchor='w')
        self._vt_verdict.pack(fill='x', pady=(4,0))

    def _run_vtlookup_hash(self):
        h = self._vt_hash.get().strip()
        if not h: messagebox.showwarning('No Hash','Enter a hash value.'); return
        threading.Thread(target=self._do_vtlookup, args=(h,), daemon=True).start()

    def _run_vtlookup_file(self):
        p = self._vt_file.get().strip()
        if not p: messagebox.showwarning('No File','Select a file.'); return
        threading.Thread(target=lambda: self._do_vtlookup(None, p), daemon=True).start()

    def _do_vtlookup(self, hash_val=None, file_path=None):
        key = self._vt_apikey.get().strip()
        ml  = MalwareHashLookup(api_key=key)
        r   = ml.lookup(hash_val) if hash_val else ml.lookup_file(file_path)
        self.after(0, lambda: self._display_vt(r))

    def _display_vt(self, r):
        self._vt_text.config(state='normal'); self._vt_text.delete('1.0','end')

        error = r.get('error','')
        if error:
            if 'not found' in error.lower():
                self._vt_text.insert('end',
                    '📋 Hash Not Found in VirusTotal Database\n\n'
                    'This means:\n'
                    '  • The file has never been submitted to VirusTotal before\n'
                    '  • OR it is a very new/private file\n'
                    '  • This does NOT mean the file is malicious\n\n'
                    f'Hash checked: {r.get("hash","")}\n\n'
                    '💡 Tip: To get results, upload the actual file to virustotal.com\n'
                    '   or use a well-known file (e.g. a system .exe from Windows)')
                self._vt_verdict.config(text='ℹ Hash not in VT database — file never submitted', fg=C['muted'])
            elif 'No API key' in error:
                self._vt_text.insert('end',
                    '🔑 No API Key Provided\n\n'
                    'Steps to get a FREE VirusTotal API key:\n'
                    '  1. Go to: https://www.virustotal.com\n'
                    '  2. Create a free account\n'
                    '  3. Go to your Profile → API Key\n'
                    '  4. Copy the key and paste it in the field above\n\n'
                    'Free key allows: 4 lookups per minute, 500 per day')
                self._vt_verdict.config(text='⚠ API Key required', fg=C['warn'])
            elif 'Invalid API' in error:
                self._vt_text.insert('end', f'❌ Invalid API Key — please check and re-enter.\n')
                self._vt_verdict.config(text='❌ Invalid API Key', fg=C['danger'])
            else:
                self._vt_text.insert('end', f'⚠ {error}\n')
                self._vt_verdict.config(text=error, fg=C['warn'])
            self._vt_text.config(state='disabled')
            return

        # Successful lookup
        for k,v in r.items():
            if k in ('verdicts','error','hash'): continue
            self._vt_text.insert('end', f'{k:<22}: {v}\n')
        if r.get('verdicts'):
            self._vt_text.insert('end','\n─── Engine Detections ──────────────────\n')
            for v in r['verdicts']: self._vt_text.insert('end', f'  {v}\n')
        self._vt_text.config(state='disabled')

        verdict = r.get('verdict_label','')
        col = (C['danger'] if 'MALWARE' in verdict else
               C['warn']   if 'Malicious' in verdict or 'Suspicious' in verdict
               else C['success'])
        self._vt_verdict.config(text=verdict, fg=col)
        self._log_write(f'VT Lookup: {verdict}')

    # ═══════════════════════════════════════════════════════
    #  PAGE 17 — KEYWORD SEARCH
    # ═══════════════════════════════════════════════════════
    def _page_keyword(self, parent):
        tk.Label(parent, text='Keyword Search in Files', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Recursively search a folder for keywords inside file contents.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))
        self._kw_folder = tk.StringVar()
        self._kw_words  = tk.StringVar()
        self._kw_case   = tk.BooleanVar(value=False)
        file_row(top, 'Search Folder:', self._kw_folder,
                 lambda: self._kw_folder.set(filedialog.askdirectory() or self._kw_folder.get()))

        wf = tk.Frame(top, bg=C['panel']); wf.pack(fill='x', pady=3)
        tk.Label(wf, text='Keywords:', font=FBD, bg=C['panel'],
                 fg=C['muted'], width=18, anchor='w').pack(side='left')
        tk.Entry(wf, textvariable=self._kw_words, font=FM,
                 bg=C['bg'], fg=C['text'], insertbackground=C['text'],
                 relief='flat', bd=0, width=45,
                 highlightthickness=1, highlightbackground=C['border']
                 ).pack(side='left', padx=6, ipady=4)
        tk.Label(wf, text='(comma separated)', font=FB,
                 bg=C['panel'], fg=C['muted']).pack(side='left')

        cf = tk.Frame(top, bg=C['panel']); cf.pack(fill='x', pady=3)
        tk.Checkbutton(cf, text='Case Sensitive', variable=self._kw_case,
                       font=FB, bg=C['panel'], fg=C['text'],
                       selectcolor=C['bg'], activebackground=C['panel']
                       ).pack(side='left')
        mbtn(top,'🔎 Search', self._run_keyword, width=14).pack(anchor='w', pady=(6,0))

        f, self._kw_tree = scrolled_tree(parent); f.pack(fill='both', expand=True)
        self._kw_status = tk.Label(parent, text='Enter keywords and select a folder.',
                                   font=FB, bg=C['bg'], fg=C['muted'], anchor='w')
        self._kw_status.pack(fill='x', pady=(4,0))

    def _run_keyword(self):
        folder = self._kw_folder.get().strip()
        words  = [w.strip() for w in self._kw_words.get().split(',') if w.strip()]
        if not folder:
            messagebox.showwarning('No Folder','Select a folder to search in.'); return
        if not os.path.isdir(folder):
            messagebox.showerror('Invalid Folder',f'Folder does not exist:\n{folder}'); return
        if not words:
            messagebox.showwarning('No Keywords','Enter at least one keyword (comma separated).'); return
        self._log_write(f'Keyword search: "{", ".join(words)}" in {folder}')
        threading.Thread(target=self._do_keyword, args=(folder, words), daemon=True).start()

    def _do_keyword(self, folder, words):
        self.after(0, lambda: self._kw_status.config(text='Searching… (this may take a moment)'))
        try:
            ks = KeywordSearcher()
            results = ks.search(folder, words, self._kw_case.get())
            stats = ks.stats
            # If no results, add debug info
            if not results and stats.get('files_scanned', 0) == 0:
                stats['files_scanned'] = -1  # signal error
            self.after(0, lambda: self._display_keyword(results, stats, ks.errors))
        except Exception as e:
            self.after(0, lambda: self._kw_status.config(
                text=f'Error: {e}', fg=C['danger']))

    def _display_keyword(self, results, stats, errors=None):
        tv = self._kw_tree
        cols = ['file','line_no','keyword','context','type']
        tv.config(columns=cols)
        for c in cols: tv.heading(c,text=c.title()); tv.column(c,width=140,minwidth=60)
        tv.column('file',    width=280)
        tv.column('context', width=380)
        for row in tv.get_children(): tv.delete(row)

        if not results:
            # Show helpful message in tree
            tv.config(columns=['message'])
            tv.heading('message', text='Result')
            tv.column('message', width=900)
            msg = (f'No matches found for keywords in folder.  '
                   f'Files scanned: {stats.get("files_scanned",0)}')
            if errors:
                msg += f'  |  Errors: {errors[0]}'
            tv.insert('','end', values=[msg])
        else:
            for r in results:
                # Shorten file path for display
                fp = r.get('file','')
                try: fp = str(Path(fp).name) + '  (' + str(Path(fp).parent) + ')'
                except: pass
                tv.insert('','end', values=[
                    fp,
                    r.get('line_no',''),
                    r.get('keyword',''),
                    r.get('context',''),
                    r.get('type',''),
                ], tags=('warn',))

        self._last_kw_results = results
        total = stats.get('total_hits', len(results))
        scanned = stats.get('files_scanned', 0)
        matched = stats.get('files_matched', 0)
        col = C['success'] if total > 0 else C['muted']
        self._kw_status.config(
            text=f"Files scanned: {scanned}  |  Files with hits: {matched}  |  Total hits: {total}",
            fg=col)
        self._log_write(f"Keyword search: {total} hits in {matched} files ({scanned} scanned).")

    # ═══════════════════════════════════════════════════════
    #  PAGE 18 — TIMELINE CHARTS
    # ═══════════════════════════════════════════════════════
    def _page_charts(self, parent):
        tk.Label(parent, text='Timeline Charts', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Generate forensic charts from your Autopsy CSV — activity timeline, file types, suspicious vs clean.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))

        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))

        # CSV path — directly on this page
        self._chart_csv = tk.StringVar()
        file_row(top, 'Autopsy CSV:', self._chart_csv, self._browse_chart_csv)

        self._chart_out = tk.StringVar(value=str(Path(__file__).parent.parent/'output'))
        file_row(top, 'Output Folder:', self._chart_out,
                 lambda: self._chart_out.set(filedialog.askdirectory() or self._chart_out.get()))

        br = tk.Frame(top, bg=C['panel']); br.pack(fill='x', pady=(8,0))
        mbtn(br,'📊 Generate Charts', self._run_charts, width=22).pack(side='left', padx=(0,8))
        mbtn(br,'📂 Open Output Folder', self._open_chart_folder,
             color=C['success'], width=22).pack(side='left')

        # Preview area — show charts as images inside the app
        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        tk.Label(res, text='Generated Charts', font=FH2, bg=C['panel'],
                 fg=C['accent2']).pack(anchor='w', pady=(0,6))
        self._chart_text = mlog(res); self._chart_text.pack(fill='both', expand=True)

    def _browse_chart_csv(self):
        p = filedialog.askopenfilename(title='Select Autopsy CSV',
                                        filetypes=[('CSV','*.csv'),('All','*.*')])
        if p:
            self._chart_csv.set(p)
            # Also load into timeline if not already loaded
            if not self._timeline:
                self.csv_path.set(p)

    def _open_chart_folder(self):
        import subprocess, platform
        folder = self._chart_out.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning('No Folder','Output folder does not exist yet.'); return
        if platform.system() == 'Windows':
            os.startfile(folder)
        elif platform.system() == 'Darwin':
            subprocess.Popen(['open', folder])
        else:
            subprocess.Popen(['xdg-open', folder])

    def _run_charts(self):
        csv_p = self._chart_csv.get().strip()
        out   = self._chart_out.get().strip()

        if not out:
            messagebox.showwarning('No Folder','Select an output folder.'); return

        # If CSV given here, load it fresh
        if csv_p and os.path.isfile(csv_p):
            self._chart_text.config(state='normal')
            self._chart_text.delete('1.0','end')
            self._chart_text.insert('end','Loading CSV…\n')
            self._chart_text.config(state='disabled')
            threading.Thread(target=self._do_charts_with_csv,
                             args=(csv_p, out), daemon=True).start()
        elif self._timeline:
            threading.Thread(target=self._do_charts, daemon=True).start()
        else:
            messagebox.showwarning('No Data',
                'Please select an Autopsy CSV file using the Browse button above.')

    def _do_charts_with_csv(self, csv_path, out):
        # Load CSV fresh for charts
        az = TimelineAnalyzer(csv_path)
        if az.load():
            az.analyse()
            self._analyzer = az
            self._timeline = az.build_timeline()
            self.after(0, lambda: self._update_stat_cards(az.stats))
        self._do_charts()

    def _update_stat_cards(self, stats):
        self._stat_cards['total_records'].config(text=str(stats.get('total_records','—')))
        self._stat_cards['suspicious_files'].config(text=str(stats.get('suspicious_files','—')))
        self._stat_cards['anomalies'].config(text=str(stats.get('anomalies','—')))

    def _do_charts(self):
        gen   = TimelineChartGenerator(self._timeline, self._chart_out.get().strip())
        paths = gen.generate_all()
        self.after(0, lambda: self._display_charts(paths))

    def _display_charts(self, paths):
        self._chart_text.config(state='normal'); self._chart_text.delete('1.0','end')
        if not paths:
            self._chart_text.insert('end','No charts generated. Install matplotlib: pip install matplotlib\n')
            self._chart_text.config(state='disabled')
            return

        self._chart_text.insert('end', f'✅ {len(paths)} chart(s) generated:\n')
        for p in paths: self._chart_text.insert('end', f'  📊 {p}\n')
        self._chart_text.config(state='disabled')

        # Show charts as images inside the GUI
        self._show_charts_in_gui(paths)
        self._log_write(f'Charts: {len(paths)} generated and displayed.')

    def _show_charts_in_gui(self, paths):
        # Remove old chart window if exists
        if hasattr(self, '_chart_win') and self._chart_win and self._chart_win.winfo_exists():
            self._chart_win.destroy()

        win = tk.Toplevel(self)
        win.title('📊 ForensiTrace — Timeline Charts')
        win.configure(bg=C['bg'])
        win.geometry('1100x700')
        self._chart_win = win

        tk.Label(win, text='📊 Forensic Timeline Charts',
                 font=('Segoe UI Semibold', 14), bg=C['bg'],
                 fg=C['accent2']).pack(pady=(12,4))
        tk.Label(win, text='Generated from your Autopsy CSV data',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(pady=(0,10))

        # Scrollable frame for charts
        canvas = tk.Canvas(win, bg=C['bg'], highlightthickness=0)
        vsb = ttk.Scrollbar(win, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(fill='both', expand=True, padx=10)

        inner = tk.Frame(canvas, bg=C['bg'])
        win_id = canvas.create_window((0,0), window=inner, anchor='nw')
        inner.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<MouseWheel>', lambda e: canvas.yview_scroll(
            int(-1*(e.delta/120)), 'units'))

        try:
            from PIL import Image, ImageTk
            self._chart_photos = []   # keep refs
            for path in paths:
                if not os.path.isfile(path): continue
                img = Image.open(path)
                # Scale to fit nicely
                max_w = 1050
                if img.width > max_w:
                    ratio = max_w / img.width
                    img = img.resize((max_w, int(img.height * ratio)), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self._chart_photos.append(photo)

                frame = mcard(inner, padx=8, pady=8)
                frame.pack(fill='x', pady=(0, 12))
                name = Path(path).stem.replace('_',' ').replace('chart','').strip().title()
                tk.Label(frame, text=f'📊 {name}', font=FH2,
                         bg=C['panel'], fg=C['accent2']).pack(anchor='w', pady=(0,6))
                tk.Label(frame, image=photo, bg=C['panel']).pack(anchor='center')

        except ImportError:
            tk.Label(inner, text='Install Pillow to preview charts: pip install pillow\n\nCharts saved to output folder.',
                     font=FB, bg=C['bg'], fg=C['warn']).pack(padx=20, pady=20)

        mbtn(win, '📂 Open Folder', self._open_chart_folder,
             color=C['success'], width=16).pack(pady=10)

    # ═══════════════════════════════════════════════════════
    #  PAGE 19 — EXPORT TO EXCEL
    # ═══════════════════════════════════════════════════════
    def _page_excel(self, parent):
        tk.Label(parent, text='Export to Excel', font=FT,
                 bg=C['bg'], fg=C['text']).pack(anchor='w', pady=(0,4))
        tk.Label(parent, text='Export ALL forensic activity to a styled .xlsx workbook — one sheet per module.',
                 font=FB, bg=C['bg'], fg=C['muted']).pack(anchor='w', pady=(0,8))
        top = mcard(parent, padx=12, pady=12); top.pack(fill='x', pady=(0,8))

        # CSV option so user can load directly here too
        self._excel_csv = tk.StringVar()
        file_row(top, 'Autopsy CSV (opt):', self._excel_csv,
                 lambda: self._excel_csv.set(
                     filedialog.askopenfilename(title='Select CSV',
                         filetypes=[('CSV','*.csv'),('All','*.*')]) or self._excel_csv.get()))

        self._excel_out = tk.StringVar(
            value=str(Path(__file__).parent.parent/'output'/'forensic_report.xlsx'))
        file_row(top, 'Output .xlsx:', self._excel_out,
                 lambda: self._excel_out.set(
                     filedialog.asksaveasfilename(defaultextension='.xlsx',
                         filetypes=[('Excel','*.xlsx')]) or self._excel_out.get()))

        tk.Label(top, text='Sheets that will be created (based on what you have analysed):',
                 font=FBD, bg=C['panel'], fg=C['muted']).pack(anchor='w', pady=(8,4))
        sheets = [
            '📋 Summary — case info, investigator, stats',
            '📅 Timeline — all Autopsy CSV records',
            '⚠ Suspicious Files — flagged items',
            '🌐 Browser History — Chrome, Edge, Firefox',
            '📧 Email Analysis — headers, IPs, warnings',
            '🖥 Event Log — Windows security events',
            '🔑 Steganography — image analysis results',
            '📱 USB Devices — connected device history',
            '🧠 Memory Dump — extracted artifacts',
            '🗑 Deleted Files — recovery artifacts',
            '🔐 Password — strength analysis results',
            '🔎 Keyword Hits — search results',
        ]
        cf = tk.Frame(top, bg=C['panel']); cf.pack(fill='x')
        for i, s in enumerate(sheets):
            tk.Label(cf, text=s, font=FB, bg=C['panel'],
                     fg=C['muted']).grid(row=i//2, column=i%2, sticky='w', padx=8, pady=1)

        mbtn(top,'📑 Export ALL to Excel', self._run_excel, width=26).pack(anchor='w', pady=(10,0))

        res = mcard(parent, padx=12, pady=12); res.pack(fill='both', expand=True)
        self._excel_text = mlog(res); self._excel_text.pack(fill='both', expand=True)
        mlog_write(self._excel_text, 'Load CSV or run any analyses first, then export everything.')

    def _run_excel(self):
        out = self._excel_out.get().strip()
        if not out: messagebox.showwarning('No Path','Specify output .xlsx path.'); return
        os.makedirs(Path(out).parent, exist_ok=True)
        threading.Thread(target=self._do_excel, daemon=True).start()

    def _do_excel(self):
        self.after(0, lambda: mlog_write(self._excel_text, 'Exporting to Excel…'))

        # If CSV path given on this page, load it first
        csv_p = self._excel_csv.get().strip()
        if csv_p and os.path.isfile(csv_p) and not self._timeline:
            az = TimelineAnalyzer(csv_p)
            if az.load():
                az.analyse()
                self._analyzer = az
                self._timeline = az.build_timeline()

        data = {}

        # ── Timeline & suspicious ──────────────────────────
        if self._timeline:
            data['Timeline'] = self._timeline
        if self._analyzer and self._analyzer.suspicious:
            data['Suspicious'] = self._analyzer.suspicious
        if self._analyzer and self._analyzer.anomalies:
            data['Anomalies'] = self._analyzer.anomalies

        # ── File metadata ──────────────────────────────────
        if self._meta_result:
            data['Metadata'] = self._meta_result

        # ── Browser history (all browsers flat) ───────────
        browser_flat = []
        for browser, bdata in self._browser_result.items():
            for rec in bdata.get('history', []):
                r = dict(rec); r['browser'] = browser
                browser_flat.append(r)
        if browser_flat:
            data['Browser'] = browser_flat

        # ── Email results ──────────────────────────────────
        if self._email_result:
            flat = {k: str(v) for k, v in self._email_result.items()
                    if k not in ('received_chain',)}
            data['Email'] = [flat]

        # ── Event log ─────────────────────────────────────
        if self._evtlog_result:
            data['Event Log'] = self._evtlog_result

        # ── Steganography ──────────────────────────────────
        if self._stego_result:
            data['Steganography'] = [self._stego_result]

        # ── USB devices ────────────────────────────────────
        if self._usb_result and self._usb_result.get('devices'):
            data['USB Devices'] = self._usb_result['devices']

        # ── Memory dump ────────────────────────────────────
        if self._mem_result:
            rows = []
            for url in self._mem_result.get('urls', []):
                rows.append({'type': 'URL', 'value': url})
            for ip in self._mem_result.get('ips', []):
                rows.append({'type': 'IP', 'value': ip})
            for s in self._mem_result.get('suspicious_strings', []):
                rows.append({'type': 'SUSPICIOUS', 'value': s})
            if rows: data['Memory Dump'] = rows

        # ── Deleted files ──────────────────────────────────
        if self._del_result and self._del_result.get('artifacts'):
            data['Deleted Files'] = self._del_result['artifacts']

        # ── Password results (if any analysed) ────────────
        if hasattr(self, '_last_pwd_result') and self._last_pwd_result:
            data['Password Check'] = [self._last_pwd_result]

        # ── Keyword search results ─────────────────────────
        if hasattr(self, '_last_kw_results') and self._last_kw_results:
            data['Keyword Hits'] = self._last_kw_results

        ok = ExcelExporter(self._excel_out.get()).export(data)
        out = self._excel_out.get()
        sheets_created = len(data)
        if ok:
            self.after(0, lambda: mlog_write(self._excel_text,
                f'✅ Excel saved: {out}\n   Sheets created: {sheets_created} ({", ".join(data.keys())})'))
            self.after(0, lambda: self._log_write(f'Excel: {sheets_created} sheets exported.'))
            self.after(0, lambda: messagebox.showinfo('Done',
                f'Excel saved:\n{out}\n\nSheets: {", ".join(data.keys())}'))
        else:
            self.after(0, lambda: mlog_write(self._excel_text,
                '❌ Failed. Run: pip install openpyxl'))

# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app = ForensiTraceApp()
    app.mainloop()