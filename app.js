const F = window.FATO;
const DC = F.dic;
const MAP = window.MAPA;
const ND = F.nd;
const N = F.n.length;
const START = new Date(`${F.start}T00:00:00`);
const YEAR = START.getFullYear();

const EMPTY = '<div class="vz">Sem dados no período selecionado.</div>';

let M = 'all';
let D0 = 0;
let D1 = ND - 1;
let ROWS = [];
let ST = {};
let SER = {};
let PRES = [];
let CIP = new Map();
let DH = [];
let drag = false;


// ============================================================
// UTILITÁRIOS
// ============================================================

const f = n => n.toLocaleString('pt-BR');

const $ = i => document.getElementById(i);

const cut = (s, n) =>
    s.length > n
        ? s.slice(0, n - 1) + '…'
        : s;

const pc = (a, b) =>
    b
        ? (100 * a / b).toFixed(1).replace('.', ',') + '%'
        : '0%';

const k = v =>
    v >= 1000
        ? (v / 1000)
            .toFixed(v >= 10000 ? 0 : 1)
            .replace('.', ',') + ' mil'
        : v;


// ============================================================
// TRADUÇÕES / CORES / DATAS
// ============================================================

const PT = {
    Russia: 'Rússia',
    Spain: 'Espanha',
    'United States': 'EUA',
    China: 'China',
    India: 'Índia',
    Canada: 'Canadá',
    Germany: 'Alemanha',
    Brazil: 'Brasil',
    Netherlands: 'Holanda',
    Japan: 'Japão',
    'South Korea': 'Coreia do Sul',
    Singapore: 'Singapura',
    France: 'França',
    'United Kingdom': 'Reino Unido',
    Italy: 'Itália',
    Ukraine: 'Ucrânia',
    Vietnam: 'Vietnã',
    Australia: 'Austrália',
    Turkey: 'Turquia',
    Poland: 'Polônia',
    Mexico: 'México',
    'South Africa': 'África do Sul',
    Indonesia: 'Indonésia',
    Thailand: 'Tailândia',
    Sweden: 'Suécia',
    Switzerland: 'Suíça',
    Iran: 'Irã',
    Pakistan: 'Paquistão',
    Belgium: 'Bélgica',
    Hungary: 'Hungria',
    Czechia: 'Tchéquia',
    Austria: 'Áustria',
    Ireland: 'Irlanda',
    Morocco: 'Marrocos',
    Israel: 'Israel',
    Egypt: 'Egito',
    Mauritius: 'Maurício',
    Rwanda: 'Ruanda'
};

const pt = n => PT[n] || n;

const G = '#4f8cff';
const C = '#22d3ee';
const R = '#fb7185';
const A = '#fbbf24';
const V = '#8b5cf6';
const GR2 = '#34d399';

const pad = n => String(n).padStart(2, '0');

const dd = i => new Date(
    YEAR,
    START.getMonth(),
    START.getDate() + i
);

const dstr = i =>
    pad(dd(i).getDate()) +
    '/' +
    pad(dd(i).getMonth() + 1);

const iso = i =>
    `${YEAR}-${pad(dd(i).getMonth() + 1)}-${pad(dd(i).getDate())}`;

const isoDay = s =>
    Math.round(
        (
            Date.UTC(
                +s.slice(0, 4),
                +s.slice(5, 7) - 1,
                +s.slice(8, 10)
            ) -
            Date.UTC(YEAR, START.getMonth(), START.getDate())
        ) / 864e5
    );

const strDay = s => {
    const [a, b] = s.split('/');

    return Math.round(
        (
            Date.UTC(YEAR, +b - 1, +a) -
            Date.UTC(YEAR, START.getMonth(), START.getDate())
        ) / 864e5
    );
};

const ico = n =>
    `<svg class="ic"><use href="#i-${n}"/></svg>`;


// ============================================================
// CONFIGURAÇÕES DOS DADOS
// ============================================================

const FSF = DC.rule.findIndex(rule =>
    rule.startsWith('File system full')
);

const GR = {
    Baixa: [7, 8],
    'Média': [9, 11],
    Alta: [12, 15]
};

const PR = i => DC.mitre[F.m[i]];

const fRule = i => DC.rule[F.r[i]];
const fAgent = i => DC.agent[F.a[i]];
const fCountry = i => DC.country[F.c[i]];
const fIp = i => DC.ip[F.ip[i]];
const fUser = i => DC.user[F.u[i]];
const fWin = i => DC.win[F.w[i]];
const fLv = i => String(F.lv[i]);
const fCve = i => DC.cve[F.cv[i]];
const fSev = i => DC.sev[F.sv[i]];
const fCvss = i => DC.cvss[F.cs[i]];
const fSw = i => DC.sw[F.sw[i]];
const fDay = i => dstr(F.d[i]);
const fTac = i => PR(i).map(p => p[0]);
const fTec = i => PR(i).map(p => p[1]);


// ============================================================
// NÚCLEO DE DADOS
// ============================================================

function pre() {
    for (const m of ['all', 'ex']) {
        const t = new Array(ND).fill(0);
        const h = t.slice();
        const g = t.slice();

        const as = Array.from(
            { length: ND },
            () => new Set()
        );

        for (let i = 0; i < N; i++) {
            if (m == 'ex' && F.r[i] == FSF) continue;

            const d = F.d[i];
            const n = F.n[i];

            t[d] += n;

            if (F.lv[i] >= 12) {
                h[d] += n;
            }

            if (F.c[i]) {
                g[d] += n;
            }

            as[d].add(F.a[i]);
        }

        SER[m] = {
            t,
            h,
            g,
            a: as.map(s => s.size)
        };
    }

    PRES = SER.all.t.map(v => v > 0);
}

const ser = key =>
    SER[M][key].map((v, i) =>
        PRES[i]
            ? v
            : null
    );

function compute() {
    ROWS = [];
    CIP = new Map();

    const ag = new Set();
    const dy = new Set();

    let n = 0;
    let hi = 0;

    for (let i = 0; i < N; i++) {
        const d = F.d[i];

        if (
            d < D0 ||
            d > D1 ||
            (M == 'ex' && F.r[i] == FSF)
        ) {
            continue;
        }

        ROWS.push(i);

        n += F.n[i];

        if (F.lv[i] >= 12) {
            hi += F.n[i];
        }

        ag.add(F.a[i]);
        dy.add(d);

        const c = F.c[i];

        if (c) {
            let s = CIP.get(c);

            if (!s) {
                CIP.set(c, s = new Set());
            }

            s.add(F.ip[i]);
        }
    }

    ST = {
        n,
        hi,
        ag: ag.size,
        days: dy.size,
        ct: CIP.size
    };
}

function agg(fn, pred, lim = 10, key) {
    const m = new Map();

    for (const i of ROWS) {
        if (pred && !pred(i)) {
            continue;
        }

        const l = fn(i, key);

        if (Array.isArray(l)) {
            for (const x of l) {
                if (x) {
                    m.set(
                        x,
                        (m.get(x) || 0) + F.n[i]
                    );
                }
            }
        } else if (l) {
            m.set(
                l,
                (m.get(l) || 0) + F.n[i]
            );
        }
    }

    return [...m]
        .sort((a, b) => b[1] - a[1])
        .slice(0, lim);
}

const sum = pred => {
    let s = 0;

    for (const i of ROWS) {
        if (!pred || pred(i)) {
            s += F.n[i];
        }
    }

    return s;
};

const rangeSum = pred => {
    let s = 0;

    for (let i = 0; i < N; i++) {
        if (
            F.d[i] >= D0 &&
            F.d[i] <= D1 &&
            pred(i)
        ) {
            s += F.n[i];
        }
    }

    return s;
};


// ============================================================
// GRÁFICOS — BARRAS HORIZONTAIS
// ============================================================

function hb(rows, col, o = {}) {
    if (!rows.length) {
        return EMPTY;
    }

    const W = o.W || 560;
    const L = o.L || 215;
    const h = 27;
    const H = rows.length * h + 4;

    const mx = Math.max(
        ...rows.map(r => r[1])
    );

    const T =
        o.tot ||
        rows.reduce(
            (a, b) => a + b[1],
            0
        );

    return (
        `<svg viewBox="0 0 ${W} ${H}">` +
        rows
            .map((r, i) => {
                const y = i * h + 2;

                const w = Math.max(
                    2,
                    (W - L - 64) * r[1] / mx
                );

                const lb = o.lab
                    ? o.lab(r[0])
                    : r[0];

                const a = o.kind
                    ? ` data-k="${o.kind}|${r[0]}" tabindex="0"`
                    : '';

                return (
                    `<g data-t="${lb}|${f(r[1])} alertas (${pc(r[1], T)})${o.kind ? '|clique para detalhes' : ''}"${a}>` +
                    `<rect class="hit" x="0" y="${y}" width="${W}" height="${h - 2}" rx="6"/>` +
                    `<text class="t" x="4" y="${y + 17}">${cut(lb, o.mx || 31)}</text>` +
                    `<rect class="b" x="${L}" y="${y + 5}" width="${w}" height="14" rx="3" fill="${col}" style="color:${col}"/>` +
                    `<text class="v" x="${L + w + 7}" y="${y + 17}">${f(r[1])}</text>` +
                    `</g>`
                );
            })
            .join('') +
        '</svg>'
    );
}


// ============================================================
// GRÁFICOS — COLUNAS
// ============================================================

function cl(rows, col, o = {}) {
    if (!rows.length) {
        return EMPTY;
    }

    const W = 560;
    const H = 232;
    const B = 34;
    const T = 24;
    const n = rows.length;
    const bw = W / n;

    const mx = Math.max(
        ...rows.map(r => r[1])
    );

    const tot = rows.reduce(
        (a, b) => a + b[1],
        0
    );

    return (
        `<svg viewBox="0 0 ${W} ${H}">` +
        `<line class="ax" x1="0" x2="${W}" y1="${H - B}" y2="${H - B}"/>` +
        rows
            .map((r, i) => {
                const h =
                    (H - B - T) *
                    r[1] /
                    mx;

                const x =
                    i * bw +
                    bw * 0.14;

                const c =
                    typeof col == 'function'
                        ? col(r[0])
                        : col;

                const a = o.kind
                    ? ` data-k="${o.kind}|${r[0]}" tabindex="0"`
                    : '';

                return (
                    `<g data-t="${o.pre || ''}${r[0]}|${f(r[1])} alertas (${pc(r[1], tot)})${o.kind ? '|clique para detalhes' : ''}"${a}>` +
                    `<rect class="hit" x="${i * bw}" y="0" width="${bw}" height="${H}"/>` +
                    `<rect class="b" x="${x}" y="${H - B - h}" width="${bw * 0.72}" height="${Math.max(h, 1.5)}" rx="3" fill="${c}" style="color:${c}"/>` +
                    `<text class="v" text-anchor="middle" x="${x + bw * 0.36}" y="${H - B - h - 7}">${k(r[1])}</text>` +
                    `<text class="t" text-anchor="middle" x="${x + bw * 0.36}" y="${H - B + 17}">${r[0]}</text>` +
                    `</g>`
                );
            })
            .join('') +
        '</svg>'
    );
}


// ============================================================
// GRÁFICO — SPARKLINE
// ============================================================

function spark(a, col) {
    if (!a.length) {
        return '';
    }

    const W = 240;
    const H = 50;
    const n = a.length;

    const mx = Math.max(
        ...a.filter(v => v != null),
        1
    );

    const x = i =>
        n > 1
            ? W * i / (n - 1)
            : W / 2;

    const y = v =>
        H - 4 -
        (H - 10) * v / mx;

    const id = 'sk' + col.slice(1);

    let seg = [];
    let cu = [];

    a.forEach((v, i) => {
        if (v == null) {
            if (cu.length) {
                seg.push(cu);
            }

            cu = [];
        } else {
            cu.push([x(i), y(v)]);
        }
    });

    if (cu.length) {
        seg.push(cu);
    }

    return (
        `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="height:50px">` +
        `<defs>` +
        `<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">` +
        `<stop offset="0" stop-color="${col}" stop-opacity=".4"/>` +
        `<stop offset="1" stop-color="${col}" stop-opacity="0"/>` +
        `</linearGradient>` +
        `</defs>` +
        seg
            .map(g => {
                const p = g
                    .map(q =>
                        q[0].toFixed(1) +
                        ',' +
                        q[1].toFixed(1)
                    )
                    .join(' ');

                return g.length < 2
                    ? ''
                    : `<polygon points="${g[0][0]},${H} ${p} ${g[g.length - 1][0]},${H}" fill="url(#${id})"/>` +
                      `<polyline points="${p}" fill="none" stroke="${col}" stroke-width="1.8" vector-effect="non-scaling-stroke"/>`;
            })
            .join('') +
        '</svg>'
    );
}


// ============================================================
// GRÁFICO — DONUT
// ============================================================

function dn2(rows, cols, kind, ctr, sub) {
    if (!rows.length) {
        return EMPTY;
    }

    const r = 62;
    const Cc = 2 * Math.PI * r;

    const t = rows.reduce(
        (a, b) => a + b[1],
        0
    );

    let off = 0;

    let o =
        '<div class="dg">' +
        '<svg viewBox="0 0 170 170">' +
        '<g transform="rotate(-90 85 85)">';

    rows.forEach((q, i) => {
        const l = Cc * q[1] / t;

        o +=
            `<circle class="sg" data-k="${kind}|${q[2] || q[0]}" data-t="${q[0]}|${f(q[1])} alertas (${pc(q[1], t)})|clique para detalhes" cx="85" cy="85" r="${r}" fill="none" stroke="${cols[i]}" stroke-width="22" stroke-dasharray="${Math.max(l - 2, .5)} ${Cc - l + 2}" stroke-dashoffset="${-off}"/>`;

        off += l;
    });

    o +=
        `</g>` +
        `<text class="t" text-anchor="middle" x="85" y="78">${sub}</text>` +
        `<text class="big" text-anchor="middle" x="85" y="104">${ctr}</text>` +
        `</svg>` +
        `<div class="dl">`;

    rows.forEach((q, i) => {
        o +=
            `<button data-k="${kind}|${q[2] || q[0]}" data-t="${q[0]}|${f(q[1])} alertas|clique para detalhes">` +
            `<i style="background:${cols[i]}"></i>` +
            `${q[0]}` +
            `<em>${f(q[1])} (${pc(q[1], t)})</em>` +
            `</button>`;
    });

    return o + '</div></div>';
}


// ============================================================
// LINHA DO TEMPO — SELEÇÃO DE PERÍODO
// ============================================================

const LW = 760;
const LH = 470;
const LL = 44;
const LB = 26;
const LT = 12;

const lx = i =>
    LL +
    (LW - LL - 8) *
    i /
    (ND - 1);

function ln(s) {
    const mx = Math.max(
        ...s.filter(v => v != null),
        1
    );

    const y = v =>
        LT +
        (LH - LT - LB) *
        (1 - v / mx);

    const bw = (LW - LL) / ND;

    let seg = [];
    let cu = [];

    s.forEach((v, i) => {
        if (v == null) {
            if (cu.length) {
                seg.push(cu);
            }

            cu = [];
        } else {
            cu.push([
                lx(i),
                y(v),
                i,
                v
            ]);
        }
    });

    if (cu.length) {
        seg.push(cu);
    }

    let o =
        `<svg viewBox="0 0 ${LW} ${LH}" id="tl" style="cursor:crosshair;user-select:none">` +
        `<defs>` +
        `<linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">` +
        `<stop offset="0" stop-color="${G}" stop-opacity=".4"/>` +
        `<stop offset="1" stop-color="${G}" stop-opacity="0"/>` +
        `</linearGradient>` +
        `</defs>` +
        [0, .5, 1]
            .map(p =>
                `<line class="ax" x1="${LL}" x2="${LW}" y1="${y(mx * p)}" y2="${y(mx * p)}"/>` +
                `<text class="t" x="0" y="${y(mx * p) + 4}">${k(Math.round(mx * p))}</text>`
            )
            .join('');

    seg.forEach(g => {
        const p = g
            .map(q =>
                q[0].toFixed(1) +
                ',' +
                q[1].toFixed(1)
            )
            .join(' ');

        o +=
            `<polygon points="${g[0][0]},${LH - LB} ${p} ${g[g.length - 1][0]},${LH - LB}" fill="url(#ga)"/>` +
            `<polyline points="${p}" fill="none" stroke="${G}" stroke-width="2" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px ${G})"/>`;
    });

    if (D0 > 0 || D1 < ND - 1) {
        o +=
            `<rect x="${LL}" y="${LT}" width="${Math.max(lx(D0) - LL, 0)}" height="${LH - LT - LB}" fill="rgba(6,8,18,.62)"/>` +
            `<rect x="${lx(D1)}" y="${LT}" width="${Math.max(LW - 8 - lx(D1), 0)}" height="${LH - LT - LB}" fill="rgba(6,8,18,.62)"/>` +
            `<rect class="brz" x="${lx(D0)}" y="${LT}" width="${lx(D1) - lx(D0)}" height="${LH - LT - LB}"/>`;
    }

    s.forEach((v, i) => {
        if (v != null) {
            o +=
                `<g data-k="dia|${i}" data-t="${dstr(i)}/${YEAR}|${f(v)} alertas|clique: regras do dia · arraste: escolher período">` +
                `<rect class="hit" x="${lx(i) - bw / 2}" y="0" width="${bw}" height="${LH - LB}"/>` +
                `</g>`;
        }
    });

    for (let i = 0; i < ND; i += 21) {
        o +=
            `<text class="t" text-anchor="middle" x="${lx(i)}" y="${LH - 6}">${dstr(i)}</text>`;
    }

    return (
        o +
        '<rect id="brs" class="brz" y="' +
        LT +
        '" height="' +
        (LH - LT - LB) +
        '" width="0" style="display:none"/></svg>'
    );
}

function brush() {
    const el = $('c3');
    let s = null;

    const dayAt = e => {
        const r = el
            .querySelector('svg')
            .getBoundingClientRect();

        return Math.max(
            0,
            Math.min(
                ND - 1,
                Math.round(
                    (
                        (e.clientX - r.left) /
                        r.width *
                        LW -
                        LL
                    ) /
                    (LW - LL - 8) *
                    (ND - 1)
                )
            )
        );
    };

    el.onmousedown = e => {
        if (
            e.button ||
            !el.querySelector('svg')
        ) {
            return;
        }

        s = {
            x: e.clientX,
            a: dayAt(e)
        };
    };

    window.addEventListener('mousemove', e => {
        if (!s) {
            return;
        }

        const b = $('brs');

        if (!b) {
            return;
        }

        if (Math.abs(e.clientX - s.x) > 6) {
            const c = dayAt(e);
            const a = Math.min(s.a, c);
            const z = Math.max(s.a, c);

            b.style.display = 'block';
            b.setAttribute('x', lx(a));
            b.setAttribute(
                'width',
                lx(z) - lx(a)
            );
        }
    });

    window.addEventListener('mouseup', e => {
        if (!s) {
            return;
        }

        const m =
            Math.abs(e.clientX - s.x) > 6;

        const c = dayAt(e);
        const a = Math.min(s.a, c);
        const z = Math.max(s.a, c);

        s = null;

        if (m) {
            drag = true;

            setTimeout(
                () => drag = false,
                60
            );

            setRange(a, z);
        }
    });
}


// ============================================================
// AUSÊNCIA DE ORIGEM
// ============================================================

const NOORIG =
    '<div class="vz">' +
    'Este período não tem IP de origem registrado.' +
    '<br>A base só traz IP e país de origem em <b>abril</b> (5.639 alertas).' +
    '<br><button class="lk" data-p="0,29">Ver abril</button>' +
    '</div>';


// ============================================================
// MAPA
// ============================================================

function mapa(rows) {
    if (!rows.length) {
        return NOORIG;
    }

    const mx = Math.max(
        ...rows.map(p => p[1])
    );

    const tot = rows.reduce(
        (a, b) => a + b[1],
        0
    );

    let o =
        `<svg viewBox="0 0 1000 394">` +
        `<path d="${MAP.dots}" fill="none" stroke="rgba(130,170,255,.2)" stroke-width="2.6" stroke-linecap="round"/>`;

    rows
        .slice()
        .reverse()
        .forEach(p => {
            const q = MAP.pts[p[0]];

            if (!q) {
                return;
            }

            const r =
                4 +
                Math.sqrt(p[1] / mx) * 26;

            const top =
                p[1] / mx > .12;

            const ips =
                (
                    CIP.get(
                        DC.country.indexOf(p[0])
                    ) || { size: 0 }
                ).size;

            o +=
                `<g data-k="pais|${p[0]}" data-t="${pt(p[0])}|${f(p[1])} alertas (${pc(p[1], tot)}) · ${ips} IPs|clique para detalhes" tabindex="0">` +
                (
                    top
                        ? `<circle class="pu" style="--r0:${r}px" cx="${q[0]}" cy="${q[1]}" r="${r}" fill="${R}"/>`
                        : ''
                ) +
                `<circle class="bub" cx="${q[0]}" cy="${q[1]}" r="${r}" fill="${R}" fill-opacity=".55" stroke="${R}"/>` +
                (
                    top
                        ? `<text class="v" x="${q[0]}" y="${q[1] - r - 6}" text-anchor="middle">${pt(p[0])}</text>`
                        : ''
                ) +
                `</g>`;
        });

    return o + '</svg>';
}


// ============================================================
// PAINEL DE DETALHES
// ============================================================

const dayN = k =>
    String(k).includes('/')
        ? strDay(k)
        : +k;

const SPC = {
    pais: {
        t: pt,
        ic: 'gl',
        p: k => i => fCountry(i) == k,
        s: [
            ['Regras mais disparadas', fRule, R, 'regra'],
            ['IPs mais ativos', fIp, V, 'ip'],
            ['Agentes alvo', fAgent, C, 'host']
        ]
    },

    nivel: {
        t: k => 'Nível ' + k,
        ic: 'ba',
        p: k => i => F.lv[i] == k,
        s: [
            ['Regras mais disparadas', fRule, A, 'regra'],
            ['Agentes', fAgent, C, 'host']
        ]
    },

    dia: {
        t: k => dstr(dayN(k)) + '/' + YEAR,
        ic: 'cl',
        p: k => i => F.d[i] == dayN(k),
        s: [
            ['Regras mais disparadas', fRule, G, 'regra'],
            ['Agentes', fAgent, C, 'host']
        ]
    },

    host: {
        t: k =>
            k
                .replace('HOST_', 'host·')
                .slice(0, 13),
        ic: 'sv',
        p: k => i => fAgent(i) == k,
        s: [
            ['Regras mais disparadas', fRule, C, 'regra'],
            ['Níveis', fLv, A, 'nivel', 12],
            ['Países de origem', fCountry, R, 'pais'],
            ['Dias com mais alertas', fDay, G, 'dia']
        ]
    },

    regra: {
        t: k => k,
        ic: 'li',
        p: k => i => fRule(i) == k,
        s: [
            ['Agentes', fAgent, C, 'host'],
            ['Níveis', fLv, A, 'nivel', 12],
            ['Dias com mais alertas', fDay, G, 'dia']
        ]
    },

    tat: {
        t: k => k,
        ic: 'gr',
        p: k => i => PR(i).some(x => x[0] == k),
        s: [
            [
                'Técnicas',
                (i, k) =>
                    PR(i)
                        .filter(x => x[0] == k)
                        .map(x => x[1]),
                A,
                'tec'
            ],
            ['Regras', fRule, G, 'regra'],
            ['Agentes', fAgent, C, 'host']
        ]
    },

    tec: {
        t: k => k,
        ic: 'ta',
        p: k => i => PR(i).some(x => x[1] == k),
        s: [
            [
                'Táticas',
                (i, k) =>
                    PR(i)
                        .filter(x => x[1] == k)
                        .map(x => x[0]),
                A,
                'tat'
            ],
            ['Regras', fRule, G, 'regra'],
            ['Agentes', fAgent, C, 'host']
        ]
    },

    cve: {
        t: k => k,
        ic: 'bg',
        p: k => i => fCve(i) == k,
        s: [
            ['Agentes afetados', fAgent, C, 'host'],
            ['Dias', fDay, G, 'dia']
        ]
    },

    sev: {
        t: k => 'Severidade ' + k,
        ic: 'al',
        p: k => i => fSev(i) == k,
        s: [
            ['Softwares afetados', fSw, A, null],
            ['CVEs mais frequentes', fCve, R, 'cve']
        ]
    },

    cvss: {
        t: k => 'Nota CVSS ' + k.replace('.', ','),
        ic: 'ba',
        p: k => i => fCvss(i) == k,
        s: [
            ['Softwares afetados', fSw, A, null],
            ['CVEs mais frequentes', fCve, R, 'cve']
        ]
    },

    ip: {
        t: k => 'IP ' + k.slice(3, 11),
        ic: 'ta',
        p: k => i => fIp(i) == k,
        s: [
            ['Regras', fRule, R, 'regra'],
            ['Agentes alvo', fAgent, C, 'host'],
            ['Dias ativos', fDay, G, 'dia']
        ]
    },

    user: {
        t: k =>
            k
                .replace('USER_', 'user·')
                .slice(0, 13),
        ic: 'us',
        p: k => i => fUser(i) == k,
        s: [
            ['Regras', fRule, V, 'regra'],
            ['Agentes', fAgent, C, 'host'],
            ['Dias', fDay, G, 'dia']
        ]
    },

    win: {
        t: k => 'Event ID ' + k,
        ic: 'mo',
        p: k => i => fWin(i) == k,
        s: [
            ['Agentes', fAgent, C, 'host'],
            ['Regras', fRule, G, 'regra'],
            ['Dias', fDay, A, 'dia']
        ]
    }
};

const LABK = {
    pais: pt,
    host: h =>
        h
            .replace('HOST_', 'host·')
            .slice(0, 13),
    ip: x => x.slice(3, 11),
    nivel: x => 'Nível ' + x
};

function dBody(kd, key) {
    if (kd == 'grp') {
        const [a, b] = GR[key];

        const r = agg(
            fLv,
            i => F.lv[i] >= a && F.lv[i] <= b,
            12
        ).sort((x, y) => x[0] - y[0]);

        return {
            t: 'Severidade ' + key,
            ic: 'ba',
            sb:
                `${f(
                    r.reduce((s, x) => s + x[1], 0)
                )} alertas no período · clique num nível`,
            b: r.length
                ? hb(r, A, {
                    kind: 'nivel',
                    W: 420,
                    L: 190,
                    lab: x => 'Nível ' + x
                })
                : EMPTY
        };
    }

    const s = SPC[kd];
    const p = s.p(key);
    const tot = sum(p);

    let sb =
        `${f(tot)} alertas no período`;

    let x = '';

    const first = ROWS.find(i => p(i));

    if (kd == 'pais') {
        sb +=
            ` · ${(CIP.get(DC.country.indexOf(key)) || { size: 0 }).size} IPs distintos`;
    }

    if (kd == 'ip' && first != null) {
        sb +=
            ` · origem: ${pt(fCountry(first))}`;
    }

    if (kd == 'cve' && first != null) {
        x =
            `<div class="lei" style="border:0;margin:0 0 4px;padding:0">` +
            `<p><b>Software:</b> ${fSw(first) || '—'}</p>` +
            `<p><b>Severidade:</b> ${fSev(first)}</p>` +
            `<p><b>Nota CVSS v3:</b> ${fCvss(first)}</p>` +
            `</div>`;
    }

    if (!tot) {
        return {
            t: s.t(key),
            ic: s.ic,
            sb: 'Sem alertas deste item no período selecionado.',
            b: ''
        };
    }

    const body = s.s
        .map(([h, fn, col, kind, lim]) => {
            const r = agg(
                fn,
                p,
                lim || 6,
                key
            );

            return r.length
                ? `<h4>${h}${kind ? ' · clique' : ''}</h4>` +
                  hb(r, col, {
                      W: 420,
                      L: 190,
                      mx: 28,
                      kind,
                      tot,
                      lab: LABK[kind]
                  })
                : '';
        })
        .join('');

    return {
        t: s.t(key),
        ic: s.ic,
        sb,
        b: x + body
    };
}

function drawer() {
    const [kd, key] = DH[DH.length - 1];
    const d = dBody(kd, key);

    $('dr').innerHTML =
        `<button class="x" aria-label="Fechar" onclick="close_()">${ico('x')}</button>` +
        (
            DH.length > 1
                ? `<button class="bk" onclick="back_()">${ico('ar')}voltar</button>`
                : ''
        ) +
        `<h3>${ico(d.ic)}${cut(d.t, 34)}</h3>` +
        `<div class="sb2">${d.sb}</div>` +
        `${d.b}`;

    $('dr').classList.add('on');
    $('dr').scrollTop = 0;
}

function open_(kd, key, chain) {
    if (!chain) {
        DH = [];
    }

    DH.push([kd, key]);
    drawer();
}

function back_() {
    DH.pop();
    drawer();
}

function close_() {
    DH = [];
    $('dr').classList.remove('on');
}


// ============================================================
// PERÍODO
// ============================================================

function setRange(a, b) {
    D0 = Math.max(
        0,
        Math.min(a, b)
    );

    D1 = Math.min(
        ND - 1,
        Math.max(a, b)
    );

    render();
}

const MESES = [
    ['Abr', 0, 29],
    ['Mai', 30, 60],
    ['Jun', 61, 90],
    ['Jul', 91, 121],
    ['Ago', 122, 152],
    ['Set', 153, ND - 1]
];

function pre_chips() {
    const P = [
        ['Tudo', 0, ND - 1],
        ...MESES,
        ['Últ. 30 dias', ND - 30, ND - 1]
    ];

    $('pre').innerHTML = P
        .map((p, i) =>
            `<button data-p="${p[1]},${p[2]}" class="${D0 == p[1] && D1 == p[2] ? 'on' : ''}">${p[0]}</button>`
        )
        .join('');
}


// ============================================================
// RENDER
// ============================================================

const L = (id, t) =>
    $(id).innerHTML =
        t
            ? '<i>▸</i>' + t
            : '';

const top1 = (r, i = 0) =>
    r[i] || ['—', 0];

function render() {
    compute();

    const e = M == 'ex';
    const n = ST.n;
    const full =
        D0 == 0 &&
        D1 == ND - 1;

    $('d0').value = iso(D0);
    $('d1').value = iso(D1);
    $('d0').min = $('d1').min = iso(0);
    $('d0').max = $('d1').max = iso(ND - 1);

    $('rs').className =
        'rs' +
        (full ? '' : ' on');

    $('rb').innerHTML =
        `<b>${D1 - D0 + 1}</b> dias · <b>${ST.days}</b> com dados`;

    pre_chips();

    $('b1').className =
        e
            ? ''
            : 'on';

    $('b2').className =
        e
            ? 'on'
            : '';

    const storm =
        !e &&
        D0 <= 81 &&
        D1 >= 80;

    $('al').innerHTML =
        storm
            ? `<div class="al">${ico('al')}<div><b>Anomalia na base:</b> 162.390 alertas "File system full", de um único host em 20 e 21/06, são 61% de tudo. Use o filtro "Sem o evento" ou escolha outro período para comparar.</div></div>`
            : '';

    const hosts = agg(
        fAgent,
        null,
        10
    );

    const cts = agg(
        fCountry,
        null,
        40
    );

    const lvs = agg(
        fLv,
        null,
        20
    ).sort(
        (a, b) => a[0] - b[0]
    );


    // ========================================================
    // KPIs
    // ========================================================

    const sl = (a, b) =>
        b.slice(D0, D1 + 1);

    const tc = top1(cts);

    const K = [
        [
            'Registros',
            f(n),
            sl(0, ser('t')),
            G,
            'ba',
            `${ST.days} dias com dados`,
            G,
            'ov'
        ],
        [
            'Agentes',
            ST.ag,
            sl(0, ser('a')),
            C,
            'sv',
            hosts.length
                ? `host principal: ${f(hosts[0][1])} alertas`
                : 'sem dados',
            A,
            'al'
        ],
        [
            'Alta severidade',
            f(ST.hi),
            sl(0, ser('h')),
            R,
            'al',
            `${pc(ST.hi, n)} dos alertas (níveis 12–15)`,
            R,
            'ov'
        ],
        [
            'Países de origem',
            ST.ct,
            sl(0, ser('g')),
            V,
            'gl',
            cts.length
                ? `${pt(tc[0])}: ${pc(tc[1], cts.reduce((s, x) => s + x[1], 0))} dos alertas com origem`
                : 'só abril tem IP de origem',
            V,
            'or'
        ]
    ];

    $('k').innerHTML = K
        .map(a =>
            `<div class="card kc s3" data-go="${a[7]}" data-t="${a[0]}|clique para abrir a seção">` +
            `<div class="kt">${a[0]}<div class="kb" style="color:${a[3]};border-color:${a[3]}55;background:${a[3]}18">${ico(a[4])}</div></div>` +
            `<div class="kv">${a[1]}</div>` +
            spark(a[2], a[3]) +
            `<div class="kn"><i style="background:${a[6]}"></i>${a[5]}</div>` +
            `</div>`
        )
        .join('');


    // ========================================================
    // VISÃO GERAL
    // ========================================================

    $('c3').innerHTML =
        ln(ser('t'));

    const pk =
        ser('t')
            .slice(D0, D1 + 1)
            .reduce(
                (m, v, i) =>
                    v != null && v > m[1]
                        ? [i + D0, v]
                        : m,
                [0, 0]
            );

    L(
        'l3',
        n
            ? `Pico em <b>${dstr(pk[0])}</b>, com <b>${f(pk[1])}</b> alertas. Arraste sobre o gráfico para filtrar um período; as quebras são dias sem exportação.`
            : 'Sem dados no período.'
    );

    const g = [
        ['Baixa (7–8)', 0, 'Baixa'],
        ['Média (9–11)', 0, 'Média'],
        ['Alta (12–15)', 0, 'Alta']
    ];

    lvs.forEach(r =>
        g[
            r[0] <= 8
                ? 0
                : r[0] <= 11
                    ? 1
                    : 2
        ][1] += r[1]
    );

    $('c2').innerHTML =
        dn2(
            g,
            [C, A, R],
            'grp',
            k(n),
            'alertas'
        );

    $('c2b').innerHTML =
        cl(
            lvs,
            l => l <= 8
                ? C
                : l <= 11
                    ? A
                    : R,
            {
                kind: 'nivel',
                pre: 'Nível '
            }
        );

    const tl = top1(
        lvs
            .slice()
            .sort(
                (a, b) => b[1] - a[1]
            )
    );

    L(
        'l2',
        n
            ? `O nível <b>${tl[0]}</b> concentra <b>${pc(tl[1], n)}</b> dos alertas. Níveis 12 a 15: <b>${f(ST.hi)}</b>.`
            : ''
    );

    const rg = agg(
        fRule,
        null,
        10
    );

    const r0 = top1(rg);

    $('c1').innerHTML =
        rg.length
            ? `<table><tr><th>#</th><th>Regra</th><th>Alertas</th><th></th><th>%</th></tr>` +
              rg
                  .map(
                      (r, i) =>
                          `<tr data-k="regra|${r[0]}" data-t="${r[0]}|${f(r[1])} alertas (${pc(r[1], n)})|clique para detalhes" tabindex="0">` +
                          `<td>${i + 1}</td>` +
                          `<td>${cut(r[0], 40)}</td>` +
                          `<td class="n">${f(r[1])}</td>` +
                          `<td><div class="pb"><i style="width:${100 * r[1] / r0[1]}%"></i></div></td>` +
                          `<td>${pc(r[1], n)}</td>` +
                          `</tr>`
                  )
                  .join('') +
              '</table>'
            : EMPTY;

    L(
        'l1',
        n
            ? `<b>${r0[0]}</b> lidera, com <b>${pc(r0[1], n)}</b> dos alertas${e ? '' : ' (inclui o evento de 20–21/06, se estiver no período)'}.`
            : ''
    );


    // ========================================================
    // AÇÕES
    // ========================================================

    const all = rangeSum(() => true);

    const fs = rangeSum(
        i => F.r[i] == FSF
    );

    const ips4 = agg(
        fIp,
        null,
        4
    );

    const gsum =
        cts.reduce(
            (s, x) => s + x[1],
            0
        );

    const cr = sum(
        i => fSev(i) == 'Critical'
    );

    const cvt = sum(
        i => F.cv[i] > 0
    );

    const sw1 = top1(
        agg(fSw, null, 1)
    );

    const act = (
        v,
        ic,
        col,
        t,
        tag,
        txt
    ) =>
        `<div class="ac" data-go="${v}">` +
        `<div class="kb" style="color:${col};border-color:${col}">${ico(ic)}</div>` +
        `<div><b>${t}<span class="tag" style="color:${col}">${tag}</span></b><p>${txt}</p></div>` +
        `</div>`;

    $('act').innerHTML =
        act(
            'al',
            'sv',
            fs > 1000 ? R : GR2,
            'Monitorar o disco',
            fs > 1000 ? 'alta' : 'ok',
            fs
                ? `<strong>${f(fs)} alertas</strong> de disco cheio (${pc(fs, all)} do período). Criar alerta de capacidade e rotação de logs.`
                : 'Nenhum alerta de disco cheio no período.'
        ) +
        act(
            'or',
            'ta',
            ips4.length ? A : GR2,
            'Bloquear força bruta no SSH',
            ips4.length ? 'média' : 'ok',
            ips4.length
                ? `<strong>${ips4.length} IPs</strong> geram ${pc(ips4.reduce((s, x) => s + x[1], 0), gsum)} dos alertas com origem. Bloquear por IP, usar fail2ban e chave SSH no lugar de senha.`
                : 'Sem origem externa registrada no período (só abril tem IP de origem).'
        ) +
        act(
            'vu',
            'bg',
            cvt ? C : GR2,
            'Atualizar software vulnerável',
            cvt ? 'contínua' : 'ok',
            cvt
                ? `<strong>${f(cvt)} alertas de CVE</strong>, ${f(cr)} críticos. Software mais afetado: ${sw1[0]}.`
                : 'Nenhum alerta de CVE no período.'
        );


    // ========================================================
    // ORIGEM
    // ========================================================

    $('c4').innerHTML =
        mapa(cts);

    $('c4b').innerHTML =
        !cts.length
            ? NOORIG
            : hb(
                cts.slice(0, 10),
                R,
                {
                    kind: 'pais',
                    lab: pt,
                    L: 105,
                    W: 340,
                    mx: 16,
                    tot: gsum
                }
            );

    const mi =
        [...CIP]
            .sort(
                (a, b) =>
                    b[1].size -
                    a[1].size
            )[0];

    L(
        'l4',
        cts.length
            ? `<b>${pt(tc[0])}</b> gera <b>${pc(tc[1], gsum)}</b> dos alertas com origem (${f(tc[1])} de ${f(gsum)}), com ${(CIP.get(DC.country.indexOf(tc[0])) || { size: 0 }).size} IPs.${mi && DC.country[mi[0]] != tc[0] ? ` ${pt(DC.country[mi[0]])} tem mais IPs (${mi[1].size}), mas menos alertas.` : ''}`
            : 'Sem origem registrada neste período (só abril tem IP de origem).'
    );

    const ip =
        agg(
            fIp,
            null,
            10
        );

    $('c5').innerHTML =
        !ip.length
            ? NOORIG
            : hb(
                ip,
                R,
                {
                    W: 900,
                    L: 260,
                    kind: 'ip',
                    tot: gsum,
                    lab: x =>
                        x.slice(3, 11) +
                        ' · ' +
                        pt(
                            fCountry(
                                ROWS.find(
                                    i =>
                                        fIp(i) == x
                                )
                            )
                        )
                }
            );

    L(
        'l5',
        ip.length
            ? `Os ${Math.min(4, ip.length)} primeiros IPs somam <b>${pc(ip.slice(0, 4).reduce((s, x) => s + x[1], 0), gsum)}</b> dos alertas com origem.`
            : ''
    );


    // ========================================================
    // MITRE ATT&CK
    // ========================================================

    const ta = agg(
        fTac,
        null,
        10
    );

    const te = agg(
        fTec,
        null,
        12
    );

    const tts =
        ta.reduce(
            (s, x) => s + x[1],
            0
        );

    $('c6').innerHTML =
        hb(
            ta,
            A,
            {
                kind: 'tat'
            }
        );

    $('c7').innerHTML =
        hb(
            te.slice(0, 10),
            G,
            {
                kind: 'tec'
            }
        );

    L(
        'l6',
        ta.length > 1
            ? `<b>${ta[0][0]}</b> e <b>${ta[1][0]}</b> são <b>${pc(ta[0][1] + ta[1][1], tts)}</b> do que o Wazuh mapeia.`
            : ta.length
                ? `<b>${ta[0][0]}</b> é a única tática mapeada.`
                : 'Nenhum alerta mapeado no MITRE neste período.'
    );

    L(
        'l7',
        te.length
            ? `<b>${te[0][0]}</b> lidera, com <b>${f(te[0][1])}</b> alertas.`
            : ''
    );


    // ========================================================
    // ALVOS
    // ========================================================

    $('c8').innerHTML =
        hb(
            hosts,
            C,
            {
                kind: 'host',
                tot: n,
                lab: LABK.host
            }
        );

    L(
        'l8',
        hosts.length
            ? `O host principal concentra <b>${f(hosts[0][1])}</b> alertas (<b>${pc(hosts[0][1], n)}</b>).`
            : ''
    );

    const us =
        agg(
            fUser,
            null,
            10
        );

    $('c9').innerHTML =
        hb(
            us,
            V,
            {
                kind: 'user',
                lab: u =>
                    u
                        .replace('USER_', 'user·')
                        .slice(0, 13)
            }
        );

    L(
        'l9',
        us.length
            ? `Um usuário concentra <b>${f(us[0][1])}</b> eventos${us[1] ? `; o segundo tem <b>${f(us[1][1])}</b>` : ''}.`
            : 'Nenhum evento com usuário no período.'
    );

    const wn =
        agg(
            fWin,
            null,
            9
        );

    $('c13').innerHTML =
        cl(
            wn,
            C,
            {
                kind: 'win',
                pre: 'Event ID '
            }
        );

    L(
        'l13',
        wn.length
            ? `O ID <b>${wn[0][0]}</b> lidera, com <b>${f(wn[0][1])}</b> eventos.`
            : ''
    );


    // ========================================================
    // VULNERABILIDADES
    // ========================================================

    const sv =
        agg(
            fSev,
            null,
            6
        );

    const cv =
        agg(
            fCve,
            null,
            500
        );

    const cs =
        agg(
            fCvss,
            null,
            6
        );

    const SC = {
        Critical: R,
        High: A,
        Medium: C,
        Low: GR2
    };

    $('c10').innerHTML =
        dn2(
            sv,
            sv.map(
                r => SC[r[0]] || V
            ),
            'sev',
            k(
                sv.reduce(
                    (s, x) => s + x[1],
                    0
                )
            ),
            'alertas'
        );

    $('c11').innerHTML =
        hb(
            cv.slice(0, 8),
            R,
            {
                kind: 'cve',
                W: 400,
                L: 130
            }
        );

    $('c12').innerHTML =
        cl(
            cs,
            A,
            {
                kind: 'cvss',
                pre: 'Nota '
            }
        );

    L(
        'l10',
        sv.length
            ? `<b>${f(sv.reduce((s, x) => s + x[1], 0))}</b> alertas em <b>${cv.length}</b> CVEs distintos.`
            : 'Nenhum alerta de CVE neste período.'
    );

    L(
        'l11',
        cv.length
            ? `<b>${cv[0][0]}</b> lidera, com <b>${cv[0][1]}</b> alertas.`
            : ''
    );

    L(
        'l12',
        cs.length
            ? `A nota <b>${cs[0][0].replace('.', ',')}</b> é a mais frequente (${f(cs[0][1])} alertas).`
            : ''
    );

    if ($('dr').classList.contains('on')) {
        drawer();
    }
}


// ============================================================
// NAVEGAÇÃO / BUSCA / EVENTOS
// ============================================================

const VW = {
    ov: [
        'Visão geral',
        'Resumo das operações de segurança'
    ],
    or: [
        'Origem dos ataques',
        'De onde vêm e quem ataca'
    ],
    mi: [
        'MITRE ATT&CK',
        'Táticas e técnicas observadas pelo Wazuh'
    ],
    al: [
        'Alvos',
        'Agentes, usuários e eventos mais afetados'
    ],
    vu: [
        'Vulnerabilidades',
        'CVEs detectadas nos endpoints'
    ]
};

function go(v) {
    document
        .querySelectorAll('.view')
        .forEach(e =>
            e.classList.toggle(
                'on',
                e.id == 'v-' + v
            )
        );

    document
        .querySelectorAll('.nv')
        .forEach(e =>
            e.classList.toggle(
                'on',
                e.dataset.go == v
            )
        );

    $('ttl').textContent = VW[v][0];
    $('sub').textContent = VW[v][1];

    close_();

    scrollTo(0, 0);

    history.replaceState(
        null,
        '',
        '#' + v
    );
}


// ============================================================
// EVENTOS — CLIQUES
// ============================================================

document.addEventListener('click', ev => {
    if (
        drag ||
        !document.contains(ev.target)
    ) {
        return;
    }

    const g =
        ev.target.closest('[data-k]');

    if (g) {
        const [
            a,
            ...b
        ] = g.dataset.k.split('|');

        open_(
            a,
            b.join('|'),
            !!ev.target.closest('#dr')
        );

        return;
    }

    const p =
        ev.target.closest('[data-p]');

    if (p) {
        const [a, b] =
            p.dataset.p.split(',');

        setRange(+a, +b);

        return;
    }

    const n =
        ev.target.closest('[data-go]');

    if (n) {
        go(n.dataset.go);
        return;
    }

    if (
        !ev.target.closest('#dr') &&
        !ev.target.closest('.srch')
    ) {
        close_();
    }
});


// ============================================================
// EVENTOS — TECLADO
// ============================================================

document.addEventListener('keydown', ev => {
    if (
        ev.key == 'Enter' &&
        document.activeElement.dataset &&
        document.activeElement.dataset.k
    ) {
        document
            .activeElement
            .dispatchEvent(
                new MouseEvent(
                    'click',
                    {
                        bubbles: true
                    }
                )
            );
    }

    if (
        ev.key == '/' &&
        document.activeElement.tagName != 'INPUT'
    ) {
        ev.preventDefault();
        $('q').focus();
    }

    if (ev.key == 'Escape') {
        $('qr').style.display = 'none';
        $('q').blur();
        close_();
    }
});


// ============================================================
// TOOLTIP
// ============================================================

const tip = $('tip');

document.addEventListener('mousemove', ev => {
    const g =
        ev.target.closest &&
        ev.target.closest('[data-t]');

    if (!g) {
        tip.style.opacity = 0;
        return;
    }

    const [a, b, c] =
        g.dataset.t.split('|');

    tip.innerHTML =
        `<b>${a}</b><br>` +
        `${b || ''}` +
        (
            c
                ? `<small>${c}</small>`
                : ''
        );

    tip.style.opacity = 1;

    tip.style.left =
        Math.min(
            ev.clientX + 16,
            innerWidth -
            tip.offsetWidth -
            10
        ) + 'px';

    tip.style.top =
        (ev.clientY + 16) + 'px';
});


// ============================================================
// BUSCA
// ============================================================

const nz = s =>
    s
        .toLowerCase()
        .normalize('NFD')
        .replace(
            /[\u0300-\u036f]/g,
            ''
        );

const tecs = [
    ...new Set(
        DC.mitre
            .flat()
            .map(p => p[1])
    )
];

const tacs = [
    ...new Set(
        DC.mitre
            .flat()
            .map(p => p[0])
    )
];

const IDX = [
    ...DC.country
        .slice(1)
        .map(c => [
            pt(c),
            'país',
            'pais',
            c
        ]),

    ...DC.cve
        .slice(1)
        .map(c => [
            c,
            'CVE',
            'cve',
            c
        ]),

    ...DC.ip
        .slice(1)
        .map(c => [
            c.slice(3, 11),
            'IP',
            'ip',
            c
        ]),

    ...DC.agent
        .map(h => [
            h
                .replace('HOST_', 'host·')
                .slice(0, 13),
            'agente',
            'host',
            h
        ]),

    ...DC.rule
        .map(r => [
            r,
            'regra',
            'regra',
            r
        ]),

    ...tacs
        .map(t => [
            t,
            'tática',
            'tat',
            t
        ]),

    ...tecs
        .map(t => [
            t,
            'técnica',
            'tec',
            t
        ]),

    ...DC.user
        .slice(1)
        .map(u => [
            u
                .replace('USER_', 'user·')
                .slice(0, 13),
            'usuário',
            'user',
            u
        ])
];

$('q').addEventListener(
    'input',
    () => {
        const q =
            nz(
                $('q')
                    .value
                    .trim()
            );

        if (!q) {
            $('qr').style.display = 'none';
            return;
        }

        const r =
            IDX
                .filter(
                    x =>
                        nz(x[0])
                            .includes(q)
                )
                .slice(0, 8);

        $('qr').innerHTML =
            r
                .map(
                    x =>
                        `<button data-i="${IDX.indexOf(x)}">${cut(x[0], 34)}<small>${x[1]}</small></button>`
                )
                .join('') ||
            '<button>Nada encontrado</button>';

        $('qr').style.display = 'block';
    }
);

$('qr').addEventListener(
    'click',
    ev => {
        const b =
            ev.target.closest('[data-i]');

        if (!b) {
            return;
        }

        const x =
            IDX[+b.dataset.i];

        $('qr').style.display = 'none';
        $('q').value = '';

        open_(
            x[2],
            x[3]
        );
    }
);


// ============================================================
// FILTRO POR DATA
// ============================================================

$('d0').onchange = () => {
    if ($('d0').value) {
        setRange(
            isoDay($('d0').value),
            D1 < isoDay($('d0').value)
                ? isoDay($('d0').value)
                : D1
        );
    }
};

$('d1').onchange = () => {
    if ($('d1').value) {
        setRange(
            D0 > isoDay($('d1').value)
                ? isoDay($('d1').value)
                : D0,
            isoDay($('d1').value)
        );
    }
};


// ============================================================
// CONTROLES PRINCIPAIS
// ============================================================

$('rs').onclick =
    () => setRange(0, ND - 1);

$('b1').onclick = () => {
    M = 'all';
    render();
};

$('b2').onclick = () => {
    M = 'ex';
    render();
};


// ============================================================
// INICIALIZAÇÃO
// ============================================================

pre();

brush();

render();

const h0 =
    (location.hash || '#ov')
        .slice(1);

go(
    h0 in VW
        ? h0
        : 'ov'
);