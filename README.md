# Dinner Roulette

A collaborative restaurant picker for groups. Create a plan, invite friends, suggest restaurants, vote, and let the wheel decide where to eat.

## Quick Start

```bash
docker compose up -d --build
```

The app will be available at `http://localhost:8081`. The first user to register becomes the admin.

## Features

- **Restaurant Lists** — Like, dislike, and want-to-try lists with notes, stars, and meal type tags
- **Plans** — Create a plan, share a code, suggest restaurants, vote, and pick a winner (random or closest)
- **Spin Wheel** — Animated wheel for random restaurant selection
- **Friends** — Friend requests, friend groups, common places, friend leaderboards
- **Chat** — Real-time plan chat with mentions, emoji, GIF search (Giphy), reactions, message editing, read receipts
- **Typing Indicators** — See who's typing in real time
- **Dietary Restrictions** — Tag plans with dietary filters (vegetarian, vegan, gluten-free, etc.)
- **Explore Nearby** — Discover restaurants near your current location
- **Calendar Export** — Export plan winners as `.ics` calendar events
- **Data Export** — Download all your data as JSON (GDPR)
- **Activity Feed** — See recent friend activity
- **Stats & Badges** — Track your dining stats, adventure score, and earn badges
- **Recurring Plans** — Schedule repeating dinner plans
- **Quick Pick / Mood Pick** — Instant random pick from your likes, or filter by cuisine
- **Dark Mode** — Auto, light, and dark themes with accent color palettes
- **PWA** — Installable as a Progressive Web App with push notifications
- **Admin Panel** — User management, SMTP/VAPID config, API keys, database backup
- **Real-time** — Socket.IO for live updates across all connected clients

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Set to `production` for production |
| `PORT` | `8080` | Internal server port |
| `DB_PATH` | `./data/db.sqlite` | SQLite database file path |
| `JWT_SECRET` | Auto-generated | Secret for JWT signing |
| `GOOGLE_API_KEY` | — | Google Places API key (for restaurant search) |
| `GIPHY_API_KEY` | — | Giphy API key (for GIF search in chat) |
| `VAPID_PUBLIC_KEY` | Auto-generated | VAPID public key for push notifications |
| `VAPID_PRIVATE_KEY` | Auto-generated | VAPID private key for push notifications |
| `VAPID_EMAIL` | — | Contact email for VAPID |
| `COOKIE_SECURE` | `false` | Set to `true` if serving over HTTPS |
| `ADMIN_USERNAME` | — | Auto-promote this username to admin on startup |

Most settings (API keys, SMTP, VAPID, JWT) can also be configured through the admin panel after first login.

## Development

```bash
# Run with Docker (recommended)
docker compose up --build

# Run tests
docker compose exec dinner-roulette npm test
```

The `public/` directory is volume-mounted, so frontend changes are reflected immediately without rebuilding.

## Tech Stack

- **Backend**: Node.js, Express, better-sqlite3, Socket.IO
- **Frontend**: Alpine.js (CDN), vanilla CSS with custom properties
- **Auth**: JWT in HttpOnly cookies, bcrypt password hashing
- **Database**: SQLite
- **Deployment**: Docker (Node 18 Alpine)

## Project Structure

```
server.js           Express app, API routes, Socket.IO, DB setup
public/
  index.html        Alpine.js template
  app.js            Alpine.js component (dinnerRoulette)
  styles.css        CSS with light/dark theme support
  manifest.json     PWA manifest
  sw.js             Service worker
tests/
  api.test.js       Integration tests (supertest + Jest)
  helpers.test.js   Unit tests
data/
  db.sqlite         SQLite database (created on first run)
  backups/          Database backups (via admin panel)
```
