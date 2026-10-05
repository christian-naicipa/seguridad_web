#!/usr/bin/env python3
"""Genera las apps de prueba con vulnerabilidades plantadas (y una app limpia).

Uso: python3 crear_apps.py [carpeta_destino]   (por defecto: pruebas/apps-generadas)
Borra y recrea cada app para que las pruebas sean reproducibles.
Todas las llaves son FALSAS: tienen el formato real pero no sirven para nada.
"""
import base64
import json
import os
import shutil
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(AQUI, "apps-generadas"))


def _jwt(rol):
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode().rstrip("=")
    cabeza = b64({"alg": "HS256", "typ": "JWT"})
    datos = b64({"iss": "supabase", "ref": "qwertyuiopasdfgh", "role": rol, "iat": 1720000000, "exp": 2035000000})
    return cabeza + "." + datos + ".FAKEsignatureFAKEsignatureFAKEsig0123456789ab"


# Las llaves se arman por partes para que este archivo no parezca contener secretos reales
# (GitHub los bloquea al subir). Son FALSAS: tienen el formato correcto pero no sirven.
JWT_SERVICE = _jwt("service" + "_role")
JWT_ANON = _jwt("anon")
OPENAI_KEY = "sk-" + "proj-" + "FAKEa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0FAKE"
STRIPE_LIVE = "sk_" + "live_" + "51FAKEabcdefghijklmnopqrstuvwxyz0123456789FAKE"
STRIPE_WHSEC = "whsec_" + "FAKEabcdefghijklmnopqrstuvwxyz012345"
SHOPIFY_TOKEN = "shp" + "at_" + "0123456789abcdef0123456789abcdef"
SHOPIFY_SECRET = "shp" + "ss_" + "00112233445566778899aabbccddeeff"
FIREBASE_WEB_KEY = "AI" + "zaSyFAKE-abcdefghijklmnopqrstuvwxyz12"
LLAVES_COMPLETAS = [OPENAI_KEY, STRIPE_LIVE, SHOPIFY_TOKEN, JWT_SERVICE]


def escribir(app, ruta, contenido):
    destino = os.path.join(BASE, app, ruta)
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "w", encoding="utf-8") as f:
        f.write(contenido.lstrip("\n"))


def git_commit(app, mensaje="primer commit"):
    carpeta = os.path.join(BASE, app)
    env = dict(os.environ, GIT_AUTHOR_NAME="Alumno", GIT_AUTHOR_EMAIL="alumno@example.com",
               GIT_COMMITTER_NAME="Alumno", GIT_COMMITTER_EMAIL="alumno@example.com")
    if not os.path.isdir(os.path.join(carpeta, ".git")):
        subprocess.run(["git", "init", "-q"], cwd=carpeta, check=True)
        # macOS crea archivos "._*" en discos externos; no son parte de la app
        with open(os.path.join(carpeta, ".git", "info", "exclude"), "a") as f:
            f.write("._*\n.DS_Store\n")
    subprocess.run(["git", "add", "-A"], cwd=carpeta, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", mensaje], cwd=carpeta, check=True, env=env)


def limpiar(app):
    shutil.rmtree(os.path.join(BASE, app), ignore_errors=True)


# ---------------------------------------------------------------------------
# App A: tienda Next.js + Supabase + Stripe (hecha con Lovable/Cursor)
# ---------------------------------------------------------------------------
def app_tienda_nextjs():
    a = "tienda-nextjs-supabase"
    limpiar(a)
    escribir(a, "package.json", json.dumps({
        "name": "mi-tienda", "private": True,
        "scripts": {"dev": "next dev", "build": "next build"},
        "dependencies": {"next": "14.1.0", "react": "18.2.0", "@supabase/supabase-js": "2.39.0", "stripe": "14.10.0"},
    }, indent=2))
    escribir(a, ".gitignore", "node_modules\n.next\n")
    escribir(a, ".env.local", f"""
NEXT_PUBLIC_SUPABASE_URL=https://qwertyuiopasdfgh.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY={JWT_ANON}
SUPABASE_SERVICE_ROLE_KEY={JWT_SERVICE}
NEXT_PUBLIC_OPENAI_API_KEY={OPENAI_KEY}
STRIPE_SECRET_KEY={STRIPE_LIVE}
""")
    escribir(a, "lib/supabaseClient.ts", f"""
import {{ createClient }} from '@supabase/supabase-js'

// lo puse directo porque con la anon key no me dejaba leer los pedidos
const supabaseUrl = 'https://qwertyuiopasdfgh.supabase.co'
const supabaseKey = '{JWT_SERVICE}'

export const supabase = createClient(supabaseUrl, supabaseKey)
""")
    escribir(a, "lib/stripe.ts", """
import Stripe from 'stripe'
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string)
""")
    escribir(a, "supabase/migrations/20240101000000_init.sql", """
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_cents integer not null
);

create table customers (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  address text
);

create table orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid references customers(id),
  total_cents integer not null,
  status text default 'pending'
);

alter table customers enable row level security;
alter table products enable row level security;

create policy "products_all" on products for all using (true);
create policy "customers_own" on customers for select using (auth.uid() = id);
""")
    escribir(a, "middleware.ts", """
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// protege /admin: solo deja pasar si hay cookie de sesion
export function middleware(req: NextRequest) {
  if (!req.cookies.get('sb-access-token')) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}

export const config = { matcher: ['/dashboard/:path*'] }
""")
    escribir(a, "app/admin/page.tsx", """
'use client'
import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabaseClient'

export default function AdminPage() {
  const [orders, setOrders] = useState<any[]>([])
  useEffect(() => {
    supabase.from('orders').select('*, customers(*)').then(({ data }) => setOrders(data ?? []))
  }, [])
  async function borrar(id: string) {
    await supabase.from('orders').delete().eq('id', id)
  }
  return (
    <main>
      <h1>Panel de administracion</h1>
      {orders.map(o => (
        <div key={o.id}>{o.customers?.email} - {o.total_cents} <button onClick={() => borrar(o.id)}>Borrar</button></div>
      ))}
    </main>
  )
}
""")
    escribir(a, "app/api/checkout/route.ts", """
import { NextResponse } from 'next/server'
import { stripe } from '@/lib/stripe'

export async function POST(request: Request) {
  const { productName, price, quantity } = await request.json()
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      price_data: { currency: 'usd', product_data: { name: productName }, unit_amount: price },
      quantity,
    }],
    success_url: 'https://mitienda.com/gracias',
    cancel_url: 'https://mitienda.com/carrito',
  })
  return NextResponse.json({ url: session.url })
}
""")
    escribir(a, "app/api/webhooks/stripe/route.ts", """
import { NextResponse } from 'next/server'
import { supabase } from '@/lib/supabaseClient'

export async function POST(request: Request) {
  const event = await request.json()
  if (event.type === 'checkout.session.completed') {
    const orderId = event.data.object.metadata.order_id
    await supabase.from('orders').update({ status: 'paid' }).eq('id', orderId)
  }
  return NextResponse.json({ received: true })
}
""")
    escribir(a, "app/components/AsistenteIA.tsx", """
'use client'
import { useState } from 'react'

export function AsistenteIA() {
  const [respuesta, setRespuesta] = useState('')
  async function preguntar(texto: string) {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.NEXT_PUBLIC_OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: texto }] }),
    })
    const j = await r.json()
    setRespuesta(j.choices[0].message.content)
  }
  return <div><button onClick={() => preguntar('hola')}>Preguntar</button><p>{respuesta}</p></div>
}
""")
    escribir(a, "app/page.tsx", """
import { AsistenteIA } from './components/AsistenteIA'
export default function Home() {
  return <main><h1>Mi tienda</h1><AsistenteIA /></main>
}
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# App B: Vite + React + Firebase + servidor Express con chatbot que tiene herramientas
# ---------------------------------------------------------------------------
def app_firebase_chatbot():
    a = "app-firebase-chatbot"
    limpiar(a)
    escribir(a, "package.json", json.dumps({
        "name": "tienda-chat", "private": True, "type": "module",
        "dependencies": {"firebase": "10.7.0", "react": "18.2.0", "express": "4.18.2", "cors": "2.8.5",
                          "openai": "4.24.0", "stripe": "14.10.0", "firebase-admin": "12.0.0"},
        "devDependencies": {"vite": "5.0.10"},
    }, indent=2))
    escribir(a, ".gitignore", "node_modules\ndist\n.env\n")
    escribir(a, ".env", f"VITE_OPENAI_API_KEY={OPENAI_KEY}\nVITE_FIREBASE_API_KEY={FIREBASE_WEB_KEY}\n")
    escribir(a, "firebase.json", json.dumps({"firestore": {"rules": "firestore.rules"}, "storage": {"rules": "storage.rules"}}, indent=2))
    escribir(a, "firestore.rules", """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
""")
    escribir(a, "storage.rules", """
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.time < timestamp.date(2025, 12, 31);
    }
  }
}
""")
    escribir(a, "src/firebase.js", f"""
import {{ initializeApp }} from 'firebase/app'
import {{ getFirestore }} from 'firebase/firestore'

const firebaseConfig = {{
  apiKey: '{FIREBASE_WEB_KEY}',
  authDomain: 'tienda-chat.firebaseapp.com',
  projectId: 'tienda-chat',
  storageBucket: 'tienda-chat.appspot.com',
}}

export const app = initializeApp(firebaseConfig)
export const db = getFirestore(app)
""")
    escribir(a, "src/chat.js", """
import OpenAI from 'openai'

const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, dangerouslyAllowBrowser: true })

export async function sugerirProducto(texto) {
  const r = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: texto }],
  })
  return r.choices[0].message.content
}
""")
    escribir(a, "server/index.js", """
import express from 'express'
import cors from 'cors'
import { admin } from './firebaseAdmin.js'
import { responderCliente } from './agente.js'

const app = express()
app.use(cors({ origin: '*' }))
app.use(express.json())

app.get('/api/admin/usuarios', async (req, res) => {
  const lista = await admin.auth().listUsers(1000)
  res.json(lista.users.map(u => ({ email: u.email, uid: u.uid })))
})

app.post('/api/admin/borrar-usuario', async (req, res) => {
  await admin.auth().deleteUser(req.body.uid)
  res.json({ ok: true })
})

app.post('/api/chat', async (req, res) => {
  const respuesta = await responderCliente(req.body.mensaje, req.body.pedidoId)
  res.json({ respuesta })
})

app.listen(3001)
""")
    escribir(a, "server/firebaseAdmin.js", """
import admin from 'firebase-admin'
admin.initializeApp()
export { admin }
""")
    escribir(a, "server/pagos.js", f"""
import Stripe from 'stripe'

const stripe = new Stripe('{STRIPE_LIVE}')

export async function reembolsar(paymentIntentId, monto) {{
  return stripe.refunds.create({{ payment_intent: paymentIntentId, amount: monto }})
}}

export async function crearCupon(porcentaje) {{
  return stripe.coupons.create({{ percent_off: porcentaje, duration: 'once' }})
}}
""")
    escribir(a, "server/agente.js", """
import OpenAI from 'openai'
import { reembolsar, crearCupon } from './pagos.js'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

const herramientas = [
  { type: 'function', function: { name: 'emitir_reembolso', description: 'Reembolsa un pedido',
    parameters: { type: 'object', properties: { paymentIntentId: { type: 'string' }, monto: { type: 'number' } } } } },
  { type: 'function', function: { name: 'crear_cupon', description: 'Crea un cupon de descuento',
    parameters: { type: 'object', properties: { porcentaje: { type: 'number' } } } } },
]

export async function responderCliente(mensaje, pedidoId) {
  const system = `Eres el asistente de la tienda. Ayuda al cliente con su pedido ${pedidoId}. Mensaje del cliente: ${mensaje}`
  const r = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'system', content: system }],
    tools: herramientas,
  })
  const llamada = r.choices[0].message.tool_calls?.[0]
  if (llamada?.function.name === 'emitir_reembolso') {
    const args = JSON.parse(llamada.function.arguments)
    await reembolsar(args.paymentIntentId, args.monto)
    return 'Listo, te devolvimos el dinero.'
  }
  if (llamada?.function.name === 'crear_cupon') {
    const args = JSON.parse(llamada.function.arguments)
    const cupon = await crearCupon(args.porcentaje)
    return `Tu cupon: ${cupon.id}`
  }
  return r.choices[0].message.content
}
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# App C: app personalizada de Shopify (Express) + tema
# ---------------------------------------------------------------------------
def app_shopify():
    a = "app-shopify"
    limpiar(a)
    escribir(a, "package.json", json.dumps({
        "name": "app-shopify-descuentos", "private": True, "type": "module",
        "dependencies": {"express": "4.18.2", "@shopify/shopify-api": "9.0.0"},
    }, indent=2))
    escribir(a, ".gitignore", "node_modules\n.env\n")
    escribir(a, ".env", "SHOPIFY_API_KEY=abc123\nSHOPIFY_API_SECRET=%s\n" % SHOPIFY_SECRET)
    escribir(a, "web/shopify.js", f"""
// cliente de la Admin API de la tienda
export const SHOP = 'mi-tienda-drop.myshopify.com'
export const ADMIN_TOKEN = '{SHOPIFY_TOKEN}'

export async function adminGraphQL(query, variables) {{
  const r = await fetch(`https://${{SHOP}}/admin/api/2024-07/graphql.json`, {{
    method: 'POST',
    headers: {{ 'X-Shopify-Access-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ query, variables }}),
  }})
  return r.json()
}}
""")
    escribir(a, "web/index.js", """
import express from 'express'
import { webhooks } from './webhooks.js'
import { adminGraphQL } from './shopify.js'

const app = express()
app.use('/webhooks', webhooks)
app.use(express.json())

// crea codigos de descuento para influencers
app.post('/api/descuentos', async (req, res) => {
  const { codigo, porcentaje } = req.body
  const r = await adminGraphQL(`mutation($input: DiscountCodeBasicInput!) { discountCodeBasicCreate(basicCodeDiscount: $input) { userErrors { message } } }`,
    { input: { title: codigo, code: codigo, customerGets: { value: { percentage: porcentaje / 100 } } } })
  res.json(r)
})

app.listen(3000)
""")
    escribir(a, "web/webhooks.js", """
import express from 'express'
import { adminGraphQL } from './shopify.js'

export const webhooks = express.Router()
webhooks.use(express.json())

// Shopify llama aqui cuando se crea un pedido -> lo mandamos al proveedor
webhooks.post('/orders-create', async (req, res) => {
  const pedido = req.body
  await fetch('https://api.proveedor-drop.com/pedidos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ items: pedido.line_items, direccion: pedido.shipping_address }),
  })
  res.sendStatus(200)
})
""")
    escribir(a, "theme/layout/theme.liquid", """
<!doctype html>
<html>
<head>
  <title>{{ shop.name }}</title>
  {{ content_for_header }}
  <script src="{{ 'custom.js' | asset_url }}" defer></script>
</head>
<body>{{ content_for_layout }}</body>
</html>
""")
    escribir(a, "theme/assets/custom.js", f"""
// muestra "X personas compraron esto hoy" consultando los pedidos reales
const TOKEN = '{SHOPIFY_TOKEN}'
async function contarVentasHoy() {{
  const r = await fetch('/admin/api/2024-07/orders.json?created_at_min=' + new Date().toISOString().slice(0, 10), {{
    headers: {{ 'X-Shopify-Access-Token': TOKEN }},
  }})
  const j = await r.json()
  document.querySelector('#ventas-hoy').textContent = j.orders.length
}}
contarVentasHoy()
""")
    escribir(a, "theme/sections/producto.liquid", """
<div class="producto">
  <h1>{{ product.title }}</h1>
  <p>{{ product.description }}</p>
  <span id="ventas-hoy"></span> personas compraron esto hoy
</div>
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# App D: tienda Next.js + Supabase hecha bien (para medir falsas alarmas)
# ---------------------------------------------------------------------------
def app_segura():
    a = "tienda-segura"
    limpiar(a)
    escribir(a, "package.json", json.dumps({
        "name": "tienda-segura", "private": True,
        "dependencies": {"next": "15.5.9", "react": "19.1.2", "@supabase/supabase-js": "2.45.0", "@supabase/ssr": "0.5.1", "stripe": "17.0.0"},
    }, indent=2))
    escribir(a, ".gitignore", "node_modules\n.next\n.env*\n!.env.example\n")
    escribir(a, ".env.example", "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\nSTRIPE_SECRET_KEY=\nSTRIPE_WEBHOOK_SECRET=\n")
    escribir(a, ".env.local", f"""
NEXT_PUBLIC_SUPABASE_URL=https://qwertyuiopasdfgh.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY={JWT_ANON}
SUPABASE_SERVICE_ROLE_KEY={JWT_SERVICE}
STRIPE_SECRET_KEY={STRIPE_LIVE}
STRIPE_WEBHOOK_SECRET={STRIPE_WHSEC}
""")
    escribir(a, "lib/supabase/client.ts", """
import { createBrowserClient } from '@supabase/ssr'
export const createClient = () =>
  createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
""")
    escribir(a, "lib/supabase/server.ts", """
import 'server-only'
import { createServerClient } from '@supabase/ssr'
import { createClient as createAdmin } from '@supabase/supabase-js'
import { cookies } from 'next/headers'

export async function createClient() {
  const store = await cookies()
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  })
}

// solo para el webhook de Stripe (codigo de servidor)
export const supabaseAdmin = createAdmin(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)
""")
    escribir(a, "lib/stripe.ts", """
import 'server-only'
import Stripe from 'stripe'
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
""")
    escribir(a, "supabase/migrations/20240101000000_init.sql", """
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_cents integer not null
);
alter table products enable row level security;
create policy "products_lectura_publica" on products for select using (true);

create table profiles (
  id uuid primary key references auth.users(id),
  is_admin boolean not null default false
);
alter table profiles enable row level security;
create policy "profiles_propio" on profiles for select using (auth.uid() = id);

create table orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  total_cents integer not null,
  status text default 'pending'
);
alter table orders enable row level security;
create policy "orders_propios" on orders for select using (auth.uid() = user_id);
""")
    escribir(a, "app/admin/page.tsx", """
import { redirect } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'

export default async function AdminPage() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) redirect('/login')
  const { data: perfil } = await supabase.from('profiles').select('is_admin').eq('id', user.id).single()
  if (!perfil?.is_admin) redirect('/')
  const { data: orders } = await supabase.from('orders').select('*')
  return <main><h1>Pedidos</h1>{orders?.map(o => <div key={o.id}>{o.total_cents}</div>)}</main>
}
""")
    escribir(a, "app/api/checkout/route.ts", """
import { NextResponse } from 'next/server'
import { stripe } from '@/lib/stripe'
import { createClient } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const { productId, quantity } = await request.json()
  const qty = Math.min(Math.max(parseInt(quantity, 10) || 1, 1), 10)
  const supabase = await createClient()
  const { data: product } = await supabase.from('products').select('name, price_cents').eq('id', productId).single()
  if (!product) return NextResponse.json({ error: 'Producto no existe' }, { status: 404 })
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price_data: { currency: 'usd', product_data: { name: product.name }, unit_amount: product.price_cents }, quantity: qty }],
    success_url: 'https://mitienda.com/gracias',
    cancel_url: 'https://mitienda.com/carrito',
  })
  return NextResponse.json({ url: session.url })
}
""")
    escribir(a, "app/api/webhooks/stripe/route.ts", """
import { NextResponse } from 'next/server'
import { stripe } from '@/lib/stripe'
import { supabaseAdmin } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const body = await request.text()
  const signature = request.headers.get('stripe-signature')!
  let event
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch {
    return NextResponse.json({ error: 'Firma invalida' }, { status: 400 })
  }
  if (event.type === 'checkout.session.completed') {
    const orderId = (event.data.object as any).metadata.order_id
    await supabaseAdmin.from('orders').update({ status: 'paid' }).eq('id', orderId)
  }
  return NextResponse.json({ received: true })
}
""")
    escribir(a, "app/page.tsx", "export default function Home() { return <main><h1>Tienda</h1></main> }\n")
    escribir(a, "next.config.js", """
const headers = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
]
module.exports = { async headers() { return [{ source: '/(.*)', headers }] } }
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# Sitio "publicado" (lo sirve servidor_prueba.py) con archivos expuestos
# ---------------------------------------------------------------------------
def sitio_publicado():
    a = "sitio-publicado"
    limpiar(a)
    escribir(a, "index.html", """
<!doctype html>
<html><head><title>Mi tienda</title>
<script type="module" src="/assets/index-a1b2c3.js"></script>
</head><body><div id="root"></div></body></html>
""")
    escribir(a, "assets/index-a1b2c3.js", f"""
const e="https://qwertyuiopasdfgh.supabase.co",t="{JWT_SERVICE}";
const o={{apiKey:"{OPENAI_KEY}"}};
function n(){{return fetch("https://api.openai.com/v1/chat/completions",{{headers:{{Authorization:"Bearer "+o.apiKey}}}})}}
//# sourceMappingURL=index-a1b2c3.js.map
""")
    escribir(a, "assets/index-a1b2c3.js.map", '{"version":3,"sources":["../src/chat.js"],"mappings":""}\n')
    escribir(a, ".env", f"OPENAI_API_KEY={OPENAI_KEY}\nSTRIPE_SECRET_KEY={STRIPE_LIVE}\n")
    escribir(a, ".git/HEAD", "ref: refs/heads/main\n")
    escribir(a, ".git/config", "[core]\n\trepositoryformatversion = 0\n")

    # Sitio SPA limpio: devuelve index.html para cualquier ruta (trampa de falsos positivos)
    b = "sitio-spa-limpio"
    limpiar(b)
    escribir(b, "index.html", """
<!doctype html>
<html><head><title>Tienda limpia</title>
<script type="module" src="/assets/app-9f8e7d.js"></script>
</head><body><div id="root"></div></body></html>
""")
    escribir(b, "assets/app-9f8e7d.js", f"""
const s="https://qwertyuiopasdfgh.supabase.co",k="{JWT_ANON}";
const f={{apiKey:"{FIREBASE_WEB_KEY}",projectId:"tienda"}};
""")

# ---------------------------------------------------------------------------
# App E: API con PostgreSQL directo (sin Supabase), vulnerable
# ---------------------------------------------------------------------------
DB_URL_PG = "postgres" + "://postgres:" + "SuperClave2024" + "@db.miempresa.com:5432/tienda"
ADO_SQLSERVER = "Server=sql.miempresa.com;Database=Tienda;User Id=sa;" + "Pass" + "word=Admin123!;"


def app_api_postgres():
    a = "api-postgres"
    limpiar(a)
    escribir(a, "package.json", json.dumps({"name": "api-tienda", "private": True, "type": "module",
                                            "dependencies": {"express": "4.21.2", "pg": "8.13.1"}}, indent=2))
    escribir(a, ".gitignore", "node_modules\n.env\n")
    escribir(a, "src/db.js", """
import pg from 'pg'
// copiado del panel del proveedor
export const pool = new pg.Pool({ connectionString: '%s', ssl: false })
""" % DB_URL_PG)
    escribir(a, "src/index.js", """
import express from 'express'
import { pool } from './db.js'

const app = express()
app.use(express.json())

// buscador de clientes
app.get('/api/clientes', async (req, res) => {
  const r = await pool.query(`SELECT id, nombre, email FROM clientes WHERE nombre ILIKE '%${req.query.q}%'`)
  res.json(r.rows)
})

// login
app.post('/api/login', async (req, res) => {
  const r = await pool.query("SELECT * FROM usuarios WHERE email = '" + req.body.email + "' AND clave = '" + req.body.clave + "'")
  res.json({ ok: r.rows.length > 0 })
})

// esto está bien: consulta con parámetros
app.get('/api/productos/:id', async (req, res) => {
  const r = await pool.query('SELECT * FROM productos WHERE id = $1', [req.params.id])
  res.json(r.rows[0])
})

app.listen(3000)
""")
    escribir(a, "db/schema.sql", """
CREATE TABLE clientes (id serial PRIMARY KEY, nombre text, email text);
CREATE TABLE usuarios (id serial PRIMARY KEY, email text, clave text);
CREATE TABLE productos (id serial PRIMARY KEY, nombre text, precio numeric);
CREATE ROLE app_tienda LOGIN SUPERUSER PASSWORD 'TiendaSegura99';
GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC;
""")
    escribir(a, "docker-compose.yml", """
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ClaveDelContenedor1
    ports:
      - "5432:5432"
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# App F: API con SQL Server, vulnerable
# ---------------------------------------------------------------------------
def app_api_sqlserver():
    a = "api-sqlserver"
    limpiar(a)
    escribir(a, "package.json", json.dumps({"name": "api-pedidos", "private": True,
                                            "dependencies": {"express": "4.21.2", "mssql": "11.0.1"}}, indent=2))
    escribir(a, ".gitignore", "node_modules\n.env\n")
    escribir(a, "src/db.js", """
const sql = require('mssql')
const config = {
  user: 'sa',
  password: 'Admin123!',
  server: 'sql.miempresa.com',
  database: 'Tienda',
  options: { encrypt: false, trustServerCertificate: true },
}
module.exports = { sql, pool: new sql.ConnectionPool(config).connect() }
""")
    escribir(a, "src/pedidos.js", """
const { sql, pool } = require('./db')

async function pedidosPorEmail(req, res) {
  const p = await pool
  const r = await p.request().query("SELECT * FROM Pedidos WHERE Email = '" + req.body.email + "'")
  res.json(r.recordset)
}

// esto está bien: parámetros
async function pedidoPorId(req, res) {
  const p = await pool
  const r = await p.request().input('id', sql.Int, req.params.id).query('SELECT * FROM Pedidos WHERE Id = @id')
  res.json(r.recordset[0])
}

module.exports = { pedidosPorEmail, pedidoPorId }
""")
    escribir(a, "src/reportes.js", "module.exports.cadena = '%s'\n" % ADO_SQLSERVER)
    escribir(a, "sql/setup.sql", """
CREATE TABLE [dbo].[Pedidos] (Id INT IDENTITY(1,1) PRIMARY KEY, Email NVARCHAR(200), Total DECIMAL(10,2));
GO
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
GO
CREATE LOGIN app_tienda WITH PASSWORD = 'LoginDeLaApp2024';
ALTER SERVER ROLE sysadmin ADD MEMBER app_tienda;
GO
""")
    git_commit(a)


# ---------------------------------------------------------------------------
# App G: API con PostgreSQL bien hecha (para medir falsas alarmas)
# ---------------------------------------------------------------------------
def app_api_postgres_segura():
    a = "api-postgres-segura"
    limpiar(a)
    escribir(a, "package.json", json.dumps({"name": "api-segura", "private": True, "type": "module",
                                            "dependencies": {"express": "4.21.2", "postgres": "3.4.5"}}, indent=2))
    escribir(a, ".gitignore", "node_modules\n.env*\n!.env.example\n")
    escribir(a, ".env.example", "DATABASE_URL=postgres" + "://app_tienda:password@localhost:5432/tienda\n")
    escribir(a, "src/db.js", """
import postgres from 'postgres'
export const sql = postgres(process.env.DATABASE_URL, { ssl: 'require', max: 10 })
""")
    escribir(a, "src/index.js", """
import express from 'express'
import { sql } from './db.js'

const app = express()
app.get('/api/clientes', async (req, res) => {
  const q = String(req.query.q || '').slice(0, 50)
  const filas = await sql`SELECT id, nombre FROM clientes WHERE nombre ILIKE ${'%' + q + '%'} LIMIT 20`
  res.json(filas)
})
app.listen(3000)
""")
    escribir(a, "db/schema.sql", """
CREATE TABLE clientes (id serial PRIMARY KEY, nombre text, email text);
CREATE ROLE app_tienda LOGIN;
GRANT SELECT, INSERT, UPDATE ON clientes TO app_tienda;
""")
    escribir(a, "docker-compose.yml", """
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "127.0.0.1:5432:5432"
""")
    git_commit(a)


if __name__ == "__main__":
    app_tienda_nextjs()
    app_firebase_chatbot()
    app_shopify()
    app_segura()
    app_api_postgres()
    app_api_sqlserver()
    app_api_postgres_segura()
    sitio_publicado()
    print("Apps de prueba creadas en", BASE)
