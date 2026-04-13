# Route Refactoring Plan

The goal of this refactoring is to preserve the current route structure while grouping routes by shared prefixes and functionality. The plan is to organize routes by meaningful API prefixes rather than creating a separate module per route.

This means:
- ` /api/profile` routes live together in one profile controller/module
- ` /api/directory` routes live together in one directory controller/module
- ` /api/admin` routes live together in one admin controller/module so `isAdmin` can be applied once at the router level
- non-admin functional groups stay together by prefix, like `/api/local-researchers`, `/api/jobs`, `/api/companies`, `/api/hottopics`, and `/api/grad-projects`

> Note: This document is a planning artifact only. No application code changes are being made here.

---

### Group A: `profile` and `directory`
These routes are customer-facing user/profile features.
- `GET /api/profile` - Get the current user profile
- `PUT /api/profile` - Update current user profile
- `POST /api/profile/avatar` - Upload the user avatar
- `GET /api/directory/profiles` - Public directory search and filtering
- `GET /api/directory/stats` - Directory statistics for the public view

### Group B: `admin`
All admin routes should be grouped under `/api/admin` so a single middleware line can protect the controller.
- `POST /api/admin/upload-researchers`
- `POST /api/admin/upload-companies`
- `GET /api/admin/pending-users`
- `POST /api/admin/approve-user`
- `POST /api/admin/import-job`
- `POST /api/admin/import-jobs-bulk`
- `POST /api/admin/external-search`
- `POST /api/admin/linkedin-scrape`
- `POST /api/admin/upload-grad-projects`

### Group C: `local-researchers`
These are application-domain routes for local researcher data.
- `GET /api/local-researchers/main-topics`
- `GET /api/local-researchers/filter`
- `POST /api/local-researchers/analyze`

### Group D: `jobs`
Job portal routes should be maintained in one group.
- `GET /api/job-filters`
- `POST /api/jobs/query`
- `POST /api/apply`
- `POST /api/jobs/add`
- `GET /api/jobs/:id/applicants`
- `DELETE /api/jobs/:id`

### Group E: `companies`
Company directory routes belong together.
- `GET /api/companies`
- `GET /api/companies/filters`
- `GET /api/companies/analytics`
- `GET /api/admin/all-companies`

### Group F: `hottopics`
Hot topics and radar management.
- `GET /api/hottopics`
- `POST /api/hottopics/add`
- `DELETE /api/hottopics/:id`

### Group G: `semantic.scholar` and search
Core search and academic analysis APIs.
- `GET /api/search`
- `POST /api/analyze`
- `GET /api/explore`

### Group H: `grad-projects`
Graduation project workflows.
- `POST /api/grad-projects/submit`
- `GET /api/grad-projects`

### Group I: misc / core
Utility and public-facing metadata.
- `GET /api/health`
- `POST /api/feedback`

### Frontend routing
The UI-serving routes remain separate from API controllers:
- `/`, `/about`, `/scanner`, `/explorer`, `/hottopics`, `/jobs`, `/local-search`, `/contact`, `/privacy`, `/api-docs`, `/login`
- `/profiles`, `/profile`, `/grad-form`, `/grad-dashboard`, `/team`
- `/linkedin-scraper`, `/digital-ic-tools`, `/analog-ic-tools`, `/general-ic-tools`, `/Docker`, `/tools`
