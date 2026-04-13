# Scholar

A Node.js + Express multi-page platform for academic discovery, researcher analysis, jobs, companies, community profiles, and graduation project listings.

**Repository:** `zizinnistore-alt/scholar`  
**Live site:** `https://scholar-phi.vercel.app`

## Overview

Scholar is built as a traditional server-delivered web application. The frontend is a collection of standalone HTML pages under `public/`, while the backend is centered in a single Express server file, `index.js`. Data storage and file uploads are handled through Supabase, and research/search features integrate with external services such as Semantic Scholar and Serper.

This README is designed to do two things:

1. work as the repo's main entry point for contributors and reviewers
2. preserve the detailed repository map from the attached documentation inside the README itself

## Core capabilities

The current repository exposes functionality across these main areas:

- academic researcher search and analysis
- paper exploration and recommendation flows
- local researcher database import and filtering
- jobs board with map/filtering/application workflows
- companies directory with analytics
- user registration, login, approval, and profile management
- public community directory
- hot topics management
- graduation projects submission and dashboard
- admin-oriented external job discovery and bulk import tooling
- static informational pages and open-source IC tools pages

## Architecture at a glance

- **Backend:** Express
- **Frontend:** Vanilla HTML, CSS, and JavaScript
- **Database and storage:** Supabase
- **Auth:** JWT + cookies, with some frontend state also mirrored in `localStorage`
- **File upload handling:** Multer
- **Spreadsheet import/export related parsing:** `xlsx`
- **External academic data:** Semantic Scholar
- **External job discovery:** Serper / Google and LinkedIn scraping

This is not a React, Next.js, or SPA-style codebase. It is closer to a classic multi-page app with backend API routes and static page delivery.

## Runtime dependencies

From `package.json`, the main dependencies currently are:

- `express`
- `axios`
- `@supabase/supabase-js`
- `bcrypt`
- `jsonwebtoken`
- `cookie-parser`
- `multer`
- `sqlite3`
- `xlsx`
- `cheerio`
- `dotenv`
- `cors`
- `@google/generative-ai` *(present in dependencies, while Gemini bootstrap code is commented in the backend)*

## Repository structure

```text
/
├─ index.js
├─ package.json
├─ nexus.db
├─ vercel.json
└─ public/
   ├─ *.html
   ├─ clogos/
   ├─ uploads/
   ├─ css/
   │  ├─ global.css
   │  ├─ team-page.css
   │  └─ pages/
   │     ├─ explorer.css
   │     ├─ local-search.css
   │     └─ scanner.css
   └─ js/
      ├─ layout.js
      ├─ Pagination.js
      ├─ search-handler.js
      ├─ seo-helper.js
      └─ pages/
         ├─ explorer.js
         └─ scanner.js
```

## Migration / Refactoring Plan

The following table tracks the progress of extracting the large `index.js` file into modular controllers, as detailed in the implementation plan:

| Controller | Status | Assignee |
| :--- | :--- | :--- |
| `auth` | 🔄 In Progress | marwan mamdouh |
| `profile` | ⏳ Not started yet | - |
| `locale.researchers` | ⏳ Not started yet | - |
| `semantic.scholar` | ⏳ Not started yet | - |
| `jop` | ⏳ Not started yet | - |
| `hot.topics` | ⏳ Not started yet | - |
| `companies` | ⏳ Not started yet | - |
| `grade.project` | ⏳ Not started yet | - |
| `admin` | ⏳ Not started yet | - |
| `misc / core` | ⏳ Not started yet | - |
| `views / frontend router` | ⏳ Not started yet | - |

## Key implementation notes

- `index.js` acts as the main backend, route registry, and integration layer.
- Shared UI logic is mostly handled in `public/js/layout.js`.
- A lot of styling is split between:
  - `public/css/global.css`
  - page-specific CSS files
  - inline `<style>` blocks inside HTML files
  - CSS injected at runtime by `layout.js`
- Several pages are available through `express.static(...)` rather than only through explicit route definitions.
- There are signs of legacy or partially unused code paths, such as:
  - `public/js/pages/scanner.js` appearing unused
  - `public/css/pages/scanner.css` appearing unused
  - duplicated `POST /api/jobs/add`
  - an admin bulk graduation upload route not protected by `isAdmin`
  - home page references to `/api/stats/users` despite that endpoint not being listed in the extracted backend routes

## Local development

### Prerequisites

- Node.js
- npm
- a configured Supabase project

### Environment variables

At minimum, the backend references:

```env
SUPABASE_URL=...
SUPABASE_KEY=...
JWT_SECRET=...
PORT=3000
```

`JWT_SECRET` and `PORT` have fallbacks in code, but supplying them explicitly is still the safer setup.

### Install

```bash
npm install
```

### Run

There is no dedicated `start` script in the current `package.json`, so run the app directly with Node:

```bash
node index.js
```

By default, the server uses `PORT` or falls back to `3000`.

## Main functional areas

### Frontend pages

The repo serves many standalone pages including:

- landing page
- scanner
- explorer
- jobs
- companies
- local search
- login / register / profile / profiles
- hot topics
- graduation form / dashboard
- team
- contact / privacy / about
- admin search and LinkedIn scraper tools
- IC tools pages
- Docker guide page

### API categories

The backend includes routes for:

- academic search and analysis
- local researcher database ingestion and filtering
- jobs and applications
- authentication and profiles
- companies directory and analytics
- graduation projects
- external job discovery and import
- community / feedback / hot topics

## Styling and script ownership

### Shared styling
- `public/css/global.css`

### Page-specific styling
- `public/css/team-page.css`
- `public/css/pages/explorer.css`
- `public/css/pages/local-search.css`
- `public/css/pages/scanner.css` *(appears unused based on the attached inspection)*

### Shared JS
- `public/js/layout.js`
- `public/js/Pagination.js`
- `public/js/search-handler.js`
- `public/js/seo-helper.js`

### Page JS
- `public/js/pages/explorer.js`
- `public/js/pages/scanner.js` *(appears unused based on the attached inspection)*

## Data model and services

The attached repo mapping identifies these main Supabase resources:

### Tables
- `users`
- `profiles`
- `academic_researchers`
- `jobs`
- `applications`
- `companies`
- `graduation_projects`
- `hot_topics`
- `feedback`

### Storage buckets
- `avatars`
- `cv-uploads`

### External services
- Semantic Scholar Graph API
- Serper / Google search
- LinkedIn HTML scraping
- Supabase
- Clearbit logo URLs
- UI Avatars fallback images
- Leaflet
- Chart.js
- SweetAlert2

## Maintenance risks worth checking first

If you are onboarding to this repo, start with these hotspots:

1. `index.js` size and route duplication
2. frontend auth state split between cookies and `localStorage`
3. page-specific inline CSS/JS embedded directly in HTML files
4. static pages exposed by `express.static`
5. unused or legacy assets around scanner/job flows
6. missing or inconsistent route protections on admin endpoints

## Detailed repository map

The following detailed documentation has been incorporated from the attached markdown file so the README remains self-contained:

---

# Scholar documentation — `zizinnistore-alt/scholar`

This document maps the current repository as inspected from the `main` branch of `https://github.com/zizinnistore-alt/scholar`.

It focuses on:
- every major functionality exposed by the app
- where that functionality lives in the repo
- which backend routes power it
- which CSS/JS files style or drive it
- implementation gaps and dead/legacy code that matter during maintenance

## High-level architecture

Scholar is **not** a component-based frontend app. It is a traditional multi-page application made of standalone HTML files under `public/`, served by a single Express backend in `index.js`. Data persistence and file storage are delegated to Supabase, while research and search features call third-party services like Semantic Scholar and Serper/Google.


## Runtime stack

From `package.json`, the main runtime dependencies are:
- Express
- Axios
- Supabase JS client
- bcrypt
- jsonwebtoken
- cookie-parser
- multer
- sqlite3
- xlsx
- cheerio
- dotenv
- CORS
- Google Generative AI package (present in dependencies, but Gemini calls are commented out in the backend bootstrap)

This means the repo currently behaves as a plain Node/Express app with client-side vanilla JS, rather than React/Next/Vue.


## Repository structure (functional view)

```text
/
├─ index.js                        # Entire Express backend and page routing
├─ package.json                    # Runtime dependencies
├─ nexus.db                        # Legacy/local DB artifact in repo root
├─ vercel.json                     # Present but effectively empty in inspected raw file
└─ public/
   ├─ *.html                       # Standalone pages with lots of inline CSS/JS
   ├─ clogos/                      # Static logo assets
   ├─ uploads/                     # Uploaded/static file directory
   ├─ css/
   │  ├─ global.css                # Main shared styling
   │  ├─ team-page.css             # Team page styling
   │  └─ pages/
   │     ├─ explorer.css
   │     ├─ local-search.css
   │     └─ scanner.css            # Appears unused
   └─ js/
      ├─ layout.js                 # Shared layout/header/footer/theme logic
      ├─ Pagination.js             # Shared pagination helper
      ├─ search-handler.js         # Shared URL sync helper
      ├─ seo-helper.js             # Shared SEO helper
      └─ pages/
         ├─ explorer.js
         └─ scanner.js             # Appears unused
```


## Shared JavaScript and what it does

- `index.js` — the entire Express backend. It also acts as the routing layer and effectively the system’s backend module registry.
- `public/js/layout.js` — shared header/footer injection, theme persistence, mobile nav behavior, logout wiring, and a shared success-toast helper.
- `public/js/Pagination.js` — reusable pagination component that syncs with URL parameters and dispatches a `paginationChanged` event.
- `public/js/search-handler.js` — shared `SearchSyncManager` helper for writing page state into the URL without full reloads.
- `public/js/seo-helper.js` — dynamic SEO/meta/JSON-LD helper. Used by the home page and jobs page.
- `public/js/pages/explorer.js` — dedicated logic for paper search/recommendation results.
- `public/js/pages/scanner.js` — dedicated scanner logic file exists, but `scanner.html` currently does **not** load it; the page uses inline logic instead.


## Where the styles live

### Global/shared styling
- `public/css/global.css` is the main shared stylesheet used across nearly every page.
- `public/js/layout.js` injects additional runtime CSS for header dropdowns, hamburger navigation, and mobile menu behavior. This means some shared styling is **not** in CSS files at all.

### Page-specific CSS files
- `public/css/team-page.css` — only used by `public/team.html`.
- `public/css/pages/explorer.css` — only used by `public/explorer.html`.
- `public/css/pages/local-search.css` — used by both `public/local-search.html` and `public/scanner.html`.
- `public/css/pages/scanner.css` — present in the repo but not referenced by the downloaded HTML/JS files I inspected, so it currently looks unused.

### Inline page styles
Most pages also contain a large inline `<style>` block inside the HTML file itself. So for many pages the “real” styling is split across:
1. `global.css`
2. page-specific CSS (if any)
3. inline `<style>` in the HTML page
4. injected nav/mobile CSS from `layout.js`


## Page-by-page map

| Page                           | Primary URL(s)                                     | Purpose                                                                                                                             | Styles                                                                                                                                 | Extra style source                                       | Scripts                                                                                                                                      |   Inline JS | API calls found in page                                                                                                                                                                                                              |
|:-------------------------------|:---------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------|------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Docker.html                    | /Docker, /Docker.html                              | Docker-for-Windows installation guide for OSIC tools.                                                                               | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css                                                              | inline <style> block                                     | Inline-only / none                                                                                                                           |           1 | None found in page file                                                                                                                                                                                                              |
| about.html                     | /about, /about.html                                | Static about/mission page.                                                                                                          | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           0 | None found in page file                                                                                                                                                                                                              |
| admin-search.html              | /admin-search.html                                 | Admin-oriented Google/Serper external jobs search page.                                                                             | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | https://cdn.jsdelivr.net/npm/sweetalert2@11, /js/layout.js                                                                                   |           1 | /api/admin/external-search                                                                                                                                                                                                           |
| api-docs.html                  | /api-docs, /api-docs.html                          | Static API overview page.                                                                                                           | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           0 | /api/analyze, /api/search?q=machine+learning, /api/search?q={query}                                                                                                                                                                  |
| apply.html                     | /apply.html                                        | Standalone application form page that submits CV + applicant details.                                                               | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css                                                              | inline <style> block                                     | Inline-only / none                                                                                                                           |           1 | /api/apply                                                                                                                                                                                                                           |
| companies.html                 | /companies.html                                    | Companies directory with filter chips, upload/import panel, location filtering, company analytics, and branch/presence exploration. | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, https://unpkg.com/leaflet/dist/leaflet.css, /css/global.css | inline <style> block + layout.js injected nav/mobile CSS | https://unpkg.com/leaflet/dist/leaflet.js, https://cdn.jsdelivr.net/npm/sweetalert2@11, https://cdn.jsdelivr.net/npm/chart.js, /js/layout.js |           1 | /api/?name=${c.name}&background=random, /api/admin/upload-companies, /api/companies/analytics?name=${encodeURIComponent(c.name)}, /api/companies/filters, /api/companies?q=${q}&category=${category}&size=${size}&country=${country} |
| contact.html                   | /contact, /contact.html                            | Static contact page with local form UI.                                                                                             | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | None found in page file                                                                                                                                                                                                              |
| explorer.html                  | /explorer, /explorer.html                          | Paper explorer for academic paper search and recommendation-by-paper mode.                                                          | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css, /css/pages/explorer.css                    | + layout.js injected nav/mobile CSS                      | /js/layout.js, /js/Pagination.js, /js/search-handler.js, https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js, /js/pages/explorer.js         |           0 | None found in page file                                                                                                                                                                                                              |
| feedback.html                  | /feedback.html                                     | Feedback submission page.                                                                                                           | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | + layout.js injected nav/mobile CSS                      | /js/layout.js                                                                                                                                |           1 | /api/feedback                                                                                                                                                                                                                        |
| grad-dashboard.html            | /grad-dashboard, /grad-dashboard.html              | Graduation project analytics dashboard and table.                                                                                   | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | https://cdn.jsdelivr.net/npm/chart.js, /js/layout.js                                                                                         |           1 | /api/grad-projects                                                                                                                                                                                                                   |
| grad-form.html                 | /grad-form, /grad-form.html                        | Graduation project submission form.                                                                                                 | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/grad-projects/submit                                                                                                                                                                                                            |
| hottopics.html                 | /hottopics, /hottopics.html                        | Hot topics feed with admin add/delete controls.                                                                                     | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/hottopics, /api/hottopics/${id}, /api/hottopics/add                                                                                                                                                                             |
| ic-tools.html                  | /digital-ic-tools, /ic-tools.html                  | Digital IC design toolchain catalog and guide.                                                                                      | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/html/z3.html                                                                                                                                                                                                                    |
| index.html                     | /, /index.html                                     | Landing page for the platform. Shows ecosystem cards, live counters, and entry points into research, companies, jobs, and projects. | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js, /js/seo-helper.js                                                                                                             |           2 | /api/companies, /api/grad-projects, /api/stats/companies, /api/stats/projects, /api/stats/users                                                                                                                                      |
| jobs.html                      | /jobs, /jobs.html                                  | Job map and jobs board with filtering, add-job modal, application workflow, applicant export, and admin user approval panel.        | https://unpkg.com/leaflet/dist/leaflet.css, https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css | inline <style> block + layout.js injected nav/mobile CSS | https://cdn.jsdelivr.net/npm/sweetalert2@11, https://unpkg.com/leaflet/dist/leaflet.js, /js/layout.js, /js/seo-helper.js                     |           2 | /api/admin/approve-user, /api/admin/pending-users, /api/job-filters, /api/jobs/${id}, /api/jobs/${jobId}/applicants, /api/jobs/add, /api/jobs/query                                                                                  |
| linkedin-scraper.html          | /linkedin-scraper, /linkedin-scraper.html          | Admin-oriented LinkedIn direct job scraping and bulk import screen.                                                                 | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | https://cdn.jsdelivr.net/npm/sweetalert2@11, /js/layout.js                                                                                   |           1 | /api/admin/all-companies, /api/admin/import-jobs-bulk, /api/admin/linkedin-scrape                                                                                                                                                    |
| local-search.html              | /local-search, /local-search.html                  | Local researcher database UI with admin upload, multi-filtering, stats, charts, and profile drilldown.                              | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css, /css/pages/local-search.css                | + layout.js injected nav/mobile CSS                      | https://cdn.jsdelivr.net/npm/sweetalert2@11, https://cdn.jsdelivr.net/npm/chart.js, /js/layout.js                                            |           1 | /api/admin/upload-researchers, /api/local-researchers/analyze, /api/local-researchers/filter, /api/local-researchers/filter?${params.toString(), /api/local-researchers/main-topics                                                  |
| login.html                     | /login, /login.html                                | Login form that authenticates and stores client-side session metadata.                                                              | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/auth/login                                                                                                                                                                                                                      |
| open-source-analog-tools.html  | /analog-ic-tools, /open-source-analog-tools.html   | Analog IC design tools catalog and guide.                                                                                           | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | None found in page file                                                                                                                                                                                                              |
| open-source-general-tools.html | /general-ic-tools, /open-source-general-tools.html | General and infrastructure tools catalog for open-source silicon work.                                                              | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | None found in page file                                                                                                                                                                                                              |
| privacy.html                   | /privacy, /privacy.html                            | Static privacy policy page.                                                                                                         | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           0 | None found in page file                                                                                                                                                                                                              |
| profile.html                   | /profile, /profile.html                            | Authenticated self-profile page with avatar upload, profile completion, and editable personal/project/skill data.                   | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/?name=, /api/profile, /api/profile/avatar                                                                                                                                                                                       |
| profiles.html                  | /profiles, /profiles.html                          | Public community directory with masked identities, filters, and summary stats.                                                      | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block                                     | js/layout.js                                                                                                                                 |           1 | /api/directory/profiles, /api/directory/stats                                                                                                                                                                                        |
| register.html                  | /register.html                                     | Large multi-step registration wizard for students, graduates, and industry users.                                                   | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | /api/auth/register                                                                                                                                                                                                                   |
| scanner.html                   | /scanner, /scanner.html                            | Global researcher scanner using Semantic Scholar author search and deep analysis.                                                   | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css, /css/pages/local-search.css                | inline <style> block + layout.js injected nav/mobile CSS | https://cdn.jsdelivr.net/npm/chart.js, https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js, /js/layout.js                                   |           1 | /api/analyze, /api/search                                                                                                                                                                                                            |
| team.html                      | /team, /team.html                                  | Public team page with grouped members and role sections.                                                                            | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css, /css/global.css, /css/team-page.css                         | + layout.js injected nav/mobile CSS                      | /js/layout.js                                                                                                                                |           1 | None found in page file                                                                                                                                                                                                              |
| tools.html                     | /tools, /tools.html                                | Landing page for the open-source silicon tooling hub.                                                                               | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css, /css/global.css                                             | inline <style> block + layout.js injected nav/mobile CSS | /js/layout.js                                                                                                                                |           1 | None found in page file                                                                                                                                                                                                              |

### Frontend delivery

- `GET /` — Serve public/index.html
- `GET /scanner` — Serve public/scanner.html
- `GET /explorer` — Serve public/explorer.html
- `GET /hottopics` — Serve public/hottopics.html
- `GET /jobs` — Serve public/jobs.html
- `GET /about` — Serve public/about.html
- `GET /api-docs` — Serve public/api-docs.html
- `GET /privacy` — Serve public/privacy.html
- `GET /contact` — Serve public/contact.html
- `GET /login` — Serve public/login.html
- `GET /local-search` — Serve public/local-search.html
- `GET /team` — Serve public/team.html
- `GET /grad-form` — Serve public/grad-form.html
- `GET /grad-dashboard` — Serve public/grad-dashboard.html
- `GET /linkedin-scraper` — Serve public/linkedin-scraper.html
- `GET /profiles` — Serve public/profiles.html
- `GET /profile` — Serve public/profile.html
- `GET /digital-ic-tools` — Serve public/ic-tools.html
- `GET /analog-ic-tools` — Serve public/open-source-analog-tools.html
- `GET /general-ic-tools` — Serve public/open-source-general-tools.html
- `GET /Docker` — Serve public/Docker.html
- `GET /tools` — Serve public/tools.html
- `express.static(public)` — Also serves static-only pages like /companies.html, /register.html, /feedback.html, /admin-search.html, /apply.html

### Academic search and analysis

- `GET /api/search` — Semantic Scholar author search by query/description; returns authors plus derived primary field.
- `POST /api/analyze` — Fetch a researcher profile from Semantic Scholar and derive metrics/collaborators/top papers.
- `GET /api/explore` — Paper search or recommendation mode against Semantic Scholar papers API.
- `POST /api/local-researchers/analyze` — Start from local DB researcher, resolve/lookup Semantic Scholar profile, then enrich with collaborators and papers.

### Local researcher database

- `POST /api/admin/upload-researchers` — Admin Excel upload into academic_researchers; extracts Semantic Scholar or Google Scholar IDs.
- `GET /api/local-researchers/main-topics` — Distinct main topics for filters.
- `GET /api/local-researchers/filter` — Filter local researchers by topic/subtopic/university/researcher/keywords with deduplication.

### Jobs and applications

- `GET /api/job-filters` — Distinct countries/companies/tracks plus active country codes for the jobs map.
- `POST /api/jobs/query` — Filter jobs table by country/track/company/text query.
- `POST /api/jobs/add` — Job creation route exists twice; the earlier authenticated version is the one Express will hit first.
- `POST /api/apply` — Upload CV to Supabase Storage bucket cv-uploads and insert application row.
- `GET /api/jobs/:id/applicants` — Owner/admin reads applications for a specific job.
- `DELETE /api/jobs/:id` — Delete job and related applications.

### Authentication and profiles

- `POST /api/auth/register` — Creates users row + profiles row; admins require approval, other roles auto-approve.
- `POST /api/auth/login` — Validates credentials, checks approval, issues JWT cookie, and returns lightweight user/profile payload.
- `GET /api/auth/logout` — Clears auth cookie.
- `GET /api/profile` — Authenticated self-profile read.
- `PUT /api/profile` — Authenticated profile update with profile create-if-missing behavior.
- `POST /api/profile/avatar` — Authenticated avatar upload to Supabase Storage avatars bucket, then stores public URL.

### Companies directory

- `POST /api/admin/upload-companies` — Admin Excel import with hyperlink mining for website/LinkedIn/Glassdoor and branch normalization.
- `GET /api/companies` — Query companies table with text, category, size, and country/presence filtering.
- `GET /api/companies/filters` — Distinct country/category/size filter values.
- `GET /api/companies/analytics` — Job timeline and latest jobs for a company name.
- `GET /api/admin/all-companies` — Autocomplete dataset merged from companies and jobs tables.

### Graduation projects

- `POST /api/grad-projects/submit` — Insert one graduation project from the public form.
- `GET /api/grad-projects` — Return all graduation projects ordered newest-first and normalize domains/is_sponsored.
- `POST /api/admin/upload-grad-projects` — Bulk Excel upload into graduation_projects (not protected by isAdmin in current code).

### External job discovery

- `POST /api/admin/external-search` — Serper-backed Google search for LinkedIn jobs.
- `POST /api/admin/import-job` — Insert a single imported job result into jobs.
- `POST /api/admin/linkedin-scrape` — Scrape LinkedIn jobs page HTML and normalize job cards.
- `POST /api/admin/import-jobs-bulk` — Bulk import scraped LinkedIn jobs while skipping duplicate apply links.

### Community and feedback

- `GET /api/admin/pending-users` — Admin reads pending user approvals.
- `POST /api/admin/approve-user` — Admin approves a user.
- `GET /api/directory/profiles` — Public community directory with masked names and hidden emails/phones.
- `GET /api/directory/stats` — Directory summary stats (totals, top university, top skill).
- `GET /api/hottopics` — List hot topics.
- `POST /api/hottopics/add` — Add hot topic.
- `DELETE /api/hottopics/:id` — Delete hot topic.
- `POST /api/feedback` — Store user feedback.



## Data model and external services

### Supabase tables/buckets referenced from `index.js`
- `users` — auth credentials, role, approval state.
- `profiles` — detailed user profile fields and JSON arrays/objects.
- `academic_researchers` — imported local researcher database.
- `jobs` — job posts and job-map data.
- `applications` — job applications.
- `companies` — company directory records with serialized `branches`.
- `graduation_projects` — project catalog and dashboard data.
- `hot_topics` — admin-managed hot-topic feed.
- `feedback` — feedback submissions.
- `avatars` — Supabase Storage bucket for profile avatars.
- `cv-uploads` — Supabase Storage bucket for uploaded CVs.

### External APIs/services
- Semantic Scholar Graph API for author search, author analysis, and paper exploration.
- Serper (Google Search proxy) for external LinkedIn job discovery.
- LinkedIn HTML scraping for direct job extraction.
- Supabase for database + file storage.
- Clearbit logo URLs and UI Avatars fallback images in frontend rendering.
- Leaflet for maps, Chart.js for charts, SweetAlert2 for modal/toast UX on several admin/data pages.


## Notable implementation findings

- The app is **server-rendered only at the file-delivery level**: the frontend is plain HTML/CSS/JS, and the backend is a single Express server file.
- Several important pages are not given clean explicit routes and are instead reachable because `express.static(public)` exposes them directly, for example `/companies.html`, `/register.html`, `/feedback.html`, `/admin-search.html`, and `/apply.html`.
- `public/scanner.html` uses `local-search.css`, not `scanner.css`.
- `public/js/pages/scanner.js` appears unused by the downloaded frontend because `scanner.html` does not include it.
- The home page script explicitly references `/api/stats/users`, but that endpoint does not exist in the backend route list I extracted.
- `POST /api/jobs/add` is declared twice in `index.js`; the earlier authenticated declaration will be matched first in Express, so the later duplicate looks like dead/legacy code.
- `POST /api/admin/upload-grad-projects` lacks `isAdmin` middleware even though it is an admin-style bulk upload endpoint.
- Authentication is hybrid: backend auth checks rely on the `auth_token` cookie, while frontend UI state (name/role/logout rendering) also relies on `localStorage` keys such as `nexus_user` and `nexus_token`.

