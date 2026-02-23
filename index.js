/* 
   ================================================================
   SCHOLAR NEXUS // COMPLETE SERVER BACKEND
   ================================================================
   Features:
   1. Academic Search & Analysis (Semantic Scholar + Gemini AI) ..... Done and need to be checked
   2. Topic Explorer (AI Keyword Mapping) ..... Done and need to be checked
   3. Hot Topics Radar (Breakthroughs) ..... Done and need to be checked
   4. Jobs Portal (Interactive Map, Filtering, Application System) ..... Done and need to be checked
   5. Academic Search & Analysis (Data Base) ..... Done and need to be checked
   6. Companies info (Data Base)  ..... in progres
   7. Graduation Projects (Form and dashboard )  ..... in progres
   ================================================================
    author: Mohamed Gad Mohaned
    ...
   ================================================================
   notes: اي كومنت بالعربي يبقي ده مهم جدا 
*/


require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'nexus-super-secret-key-2024';
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const os = require('os');
const xlsx = require('xlsx');

// --- APP CONFIGURATION ---
const app = express();
const port = process.env.PORT || 3000;

// Initialize Google Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'public/uploads/jobs');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer Storage Configuration (Dynamic Folder per Job)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const jobId = req.body.jobId || 'misc'; 
        const dir = path.join(__dirname, `public/uploads/jobs/${jobId}`);
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage, limits: { fileSize: 5 * 1024 * 1024 } });
const uploadTemp = multer({ storage: multer.memoryStorage() });
// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// --- DATABASE INITIALIZATION (SQLite) ---
const db = new sqlite3.Database('./nexus.db', (err) => {
    if (err) console.error("DB Error:", err.message);
    else console.log(" Connected to SQLite database.");
    initDB();
});

const isAdmin = (req, res, next) => {
    const token = req.cookies.auth_token; // tokens from cookies

    if (!token) {
        return res.status(401).json({ error: "Access Denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: "Access Denied. Admins only." });
        }
        req.user = decoded; // save if needed
        next(); // pass
    } catch (ex) {
        res.status(400).json({ error: "Invalid token." });
    }
};

function initDB() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            is_approved INTEGER DEFAULT 0 -- 0: pending, 1: approved
        )`);


        db.run("DELETE FROM users WHERE email = 'admin@nexus.com'");

        db.get("SELECT count(*) as count FROM users WHERE role = 'admin'", async (err, row) => {
            if (row && row.count === 0) {
                const hashed = await bcrypt.hash('admin123', 10); 
                db.run("INSERT INTO users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)", 
                ['Admin', 'admin@nexus.com', hashed, 'admin', 1]);
                console.log("[DB] Default Admin created: admin@nexus.com / admin123");
            }
        });
        // Update Applications Table
        db.run(`CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jobId INTEGER,
            applicantName TEXT,
            applicantEmail TEXT,
            applicantPhone TEXT,      -- NEW
            cvPath TEXT,              -- NEW: Path to the file
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS hot_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            field TEXT,
            type TEXT,       
            status TEXT,     
            tags TEXT,
            link TEXT,           -- new field for link
            priority INTEGER DEFAULT 0  -- new field for order
        )`);

        
        
        // Update Jobs Table
        db.run(`CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER,         -- NEW: Who posted the job
            title TEXT,
            company TEXT,
            country TEXT,
            country_code TEXT,
            track TEXT,
            type TEXT,
            seniority TEXT,
            description TEXT,
            requirements TEXT,
            salary TEXT,
            apply_link TEXT,          -- NEW: External link (optional)
            posted_at DATE DEFAULT CURRENT_DATE
        )`);

         // New Table: Local Researchers from CSV
        db.run(`CREATE TABLE IF NOT EXISTS local_researchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, affiliation TEXT, country TEXT, keywords TEXT, scholar_url TEXT
        )`);

        // NEW RESEARCHER TABLE STRUCTURE
        db.run(`CREATE TABLE IF NOT EXISTS academic_researchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            affiliation TEXT,
            main_topic TEXT,
            subtopics TEXT,
            scholar_id TEXT
        )`);

        // 2. Create Companies Table with new columns
        db.run(`CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            category TEXT,
            industry TEXT,
            size TEXT,             -- NEW: Employee Count
            website TEXT,
            linkedin TEXT,         -- NEW: LinkedIn URL
            branches TEXT,         -- NEW: JSON String containing all locations/presence types
            hq_country TEXT        -- The primary or first detected country
        )`);


        // Seed Data Update
        db.get("SELECT count(*) as count FROM jobs", (err, row) => {

            if (row.count === 0) {
                const stmt = db.prepare("INSERT INTO jobs (title, company, country, country_code, track, type, seniority, description, requirements, salary) VALUES (?,?,?,?,?,?,?,?,?,?)");
                
                const seeds = [
                    [
                        'AI Research Scientist', 'DeepMind', 'United Kingdom', 'GB', 'Computer Science & AI', 'Full-time', 'Senior',
                        'Leading research in AGI and reinforcement learning.',
                        'Ph.D. in Computer Science|5+ years in PyTorch|Published at NeurIPS/ICML',
                        '$120k - $180k'
                    ],
                    [
                        'Embedded Systems Engineer', 'Siemens', 'Germany', 'DE', 'Electronics & Hardware', 'Full-time', 'Mid-Level',
                        'Developing firmware for automotive microcontrollers.',
                        'C/C++ Proficiency|Experience with RTOS|PCB Design basics',
                        '€70k - €90k'
                    ],
                    [
                        'Frontend Developer', 'Instabug', 'Egypt', 'EG', 'Computer Science & AI', 'Remote', 'Junior',
                        'Building responsive dashboards for bug reporting tools.',
                        'React.js Mastery|TypeScript|HTML5 & CSS3',
                        'Competitive'
                    ],
                    [
                        'Bioinformatics Analyst', 'Pfizer', 'United States', 'US', 'Biotechnology', 'Contract', 'Entry',
                        'Analyzing genomic data sequences for vaccine trials.',
                        'Python & R|Genomics background|Data Visualization',
                        '$50/hr'
                    ]
                ];

                seeds.forEach(s => stmt.run(s));
                stmt.finalize();
            }
        });
    });
}

// --- FRONTEND ROUTES (HTML PAGES) ---

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/scanner', (req, res) => res.sendFile(path.join(__dirname, 'public', 'scanner.html')));
app.get('/explorer', (req, res) => res.sendFile(path.join(__dirname, 'public', 'explorer.html')));
app.get('/hottopics', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hottopics.html')));
app.get('/jobs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'jobs.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));
app.get('/api-docs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'api-docs.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public', 'contact.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/local-search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'local-search.html')));




// ================================================================
//  SECTION 1: JOB PORTAL API
// ================================================================

/**
 * API: Get Job Filters & Map Data
 * Returns unique countries, companies, and tracks to populate UI dropdowns.
 * Also returns 'activeCountryCodes' to color the map blue.
 */

// Helper: robust CSV row parser 
function parseCSVRow(str) {
    const result =[];
    let curr = ''; let inQuotes = false;
    for (let i = 0; i < str.length; i++) {
        let c = str; // SOLVED
        if (c === '"') inQuotes = !inQuotes;
        else if (c === ',' && !inQuotes) { result.push(curr.trim()); curr = ''; } 
        else curr += c;
    }
    result.push(curr.trim());
    return result;
}


// Helper: Clean academic titles from names to fix S2 API calls
function cleanName(name) {
    return name.replace(/^(Professor\.|Professor|Prof\.|Dr\.|PhD Candidate at|PhD Candidate|Associate Professor|Assistant Professor|Ph\.D\.|MSc)\s+/gi, '')
               .replace(/,.*/, '') // Remove anything after a comma 
               .trim();
}
// ================================================================
//  SECTION 1: LOCAL RESEARCHER DB API
// ================================================================

// 1. Upload Excel Route (Smart ID Extractor)
app.post('/api/admin/upload-researchers',
    isAdmin,
    uploadTemp.single('file'),
    (req, res) => {

    if (!req.file || !req.file.buffer) {
        return res.status(400).json({error: "No file uploaded or invalid format"});
    }
    
    const clearDb = req.body.clear_db === 'true';

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });

        db.serialize(() => {
            if (clearDb) db.run("DELETE FROM academic_researchers"); 

            const stmt = db.prepare("INSERT INTO academic_researchers (name, affiliation, main_topic, subtopics, scholar_id) VALUES (?, ?, ?, ?, ?)");
            let totalInserted = 0;

            const sheetsEntries = Object.entries(workbook.Sheets);
            
            sheetsEntries.forEach(entry => {
                const sheetName = entry.at(0);
                const sheet = entry.at(1);
                const rows = xlsx.utils.sheet_to_json(sheet, { header: 1 });

                for (let i = 1; i < rows.length; i++) {
                    const cols = rows.at(i);
                    if (!cols || cols.length === 0) continue;

                    const name = cols.at(0) || '';       
                    const affil = cols.at(1) || '';      
                    const subtopics = cols.at(2) || '';  
                    const link = cols.at(3) || '';       

                    if (typeof name !== 'string' || name.trim() === '' || name.toLowerCase().includes('name')) {
                        continue;
                    }

                    // === extract ID ===
                    let scholar_id = '';
                    if (typeof link === 'string') {
                        // 1. if Semantic Scholar (just numbers)
                        if (link.includes('semanticscholar.org')) {
                            const match = link.match(/author\/(\d+)/);
                            if (match) scholar_id = match.at(1);
                        } 
                        // 2. if Google Scholar (letters and numbers)
                        else if (link.includes('user=')) {
                            const parts = link.split('user=');
                            if (parts.length > 1) {
                                scholar_id = parts.at(1).split('&').at(0);
                            }
                        }
                    }

                    const topicToSave = (sheetName && sheetName !== 'Sheet1') ? sheetName.trim() : (req.body.main_topic || 'Uncategorized');
                    
                    stmt.run(name, affil, topicToSave, subtopics, scholar_id);
                    totalInserted++;
                }
            });
            
            stmt.finalize();
            res.json({success: true, message: `Database synced! Added ${totalInserted} researchers.`});
        });

    } catch (err) {
        console.error("Excel Parsing Error:", err);
        res.status(500).json({error: "Failed to parse file."});
    }
});

// 2. Fetch distinct Main Topics for the dropdown
app.get('/api/local-researchers/main-topics', (req, res) => {
    db.all(`SELECT DISTINCT main_topic FROM academic_researchers WHERE main_topic IS NOT NULL AND main_topic != ''`,[], (err, rows) => {
        if (err) return res.status(500).json({error: err.message});
        res.json(rows.map(r => r.main_topic));
    });
});

// 3. New Specific Filter Endpoint
app.get('/api/local-researchers/filter', (req, res) => {
    const { main_topic, subtopic, university, researcher } = req.query;
    
    let sql = `SELECT * FROM academic_researchers WHERE 1=1`;
    const params = [];
    
    if (main_topic) { sql += ` AND main_topic = ?`; params.push(main_topic); }
    if (subtopic) { sql += ` AND subtopics LIKE ?`; params.push(`%${subtopic}%`); }
    if (university) { sql += ` AND affiliation LIKE ?`; params.push(`%${university}%`); }
    if (researcher) { sql += ` AND name LIKE ?`; params.push(`%${researcher}%`); }
    
    // بص لو حد هيعدل بعدي في كام نوت مهمه لحاجات مسحتهم و حاجات كان لازم تتضاف 
    // الحته دي كنت حاططها علشان مبعتش كل حاجه من الداتا بيز للفرونت مباشر 
    // بس كان فيه مشكلة اني هبقي مضطر احسب حسابات الداش بورد في الباك اند و ابعتها للفرونت فانا مش هعمل كده
    // طبعا المفروض اني كنت اخطط لده من الاول بس ما علينا لو لقيت نفسك مضطر ترجع لهنا يعني و تقلل الي بيتبعت للفرونت 
    //عدل بس هنا و خد بالك من تحديث الداش بورد  في الصفحة دي 
    // REMOVED: sql += ` LIMIT 150`;  <-- DELETE THIS LINE
    // If you really want a safety cap, make it huge like 10000
    // sql += ` LIMIT 10000`; 

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({error: err.message});
        res.json(rows);
    });
});

// 4. Detailed Analyze (Smart ID or Name Search)
app.post('/api/local-researchers/analyze', async (req, res) => {
    const id = req.body.id;
    
    db.get("SELECT * FROM academic_researchers WHERE id = ?", Array.of(id), async (err, localData) => {
        if (err || !localData) {
            return res.status(404).json({error: "Researcher not found in local DB"});
        }
        
        try {
            let s2AuthorData = null;
            let authorIdToFetch = null;
            const storedId = localData.scholar_id || '';

            
            
            
            if (/^\d+$/.test(storedId)) {
                console.log(`[Method] Using Direct Semantic Scholar ID: ${storedId}`);
                authorIdToFetch = storedId;
            } 
            
            else {
                console.log(`[Method] Google ID detected (${storedId}), falling back to Smart Name Search.`);
                
                
                let cleanQueryName = localData.name.split(',').at(0); 
                
                
                const titles = ["Professor", "Prof.", "Dr.", "Eng.", "PhD Candidate", "Associate Professor", "Assistant Professor", "MSc", "Ph.D."];
                titles.forEach(t => {
                    cleanQueryName = cleanQueryName.replace(new RegExp(`\\b${t}\\b`, 'gi'), '');
                });
                
                cleanQueryName = cleanQueryName.replace(/\./g, ' ').replace(/\s+/g, ' ').trim();

                
                const searchRes = await axios.get(`https://api.semanticscholar.org/graph/v1/author/search`, {
                    params: { query: cleanQueryName, limit: 1, fields: 'authorId' },
                    headers: { 'x-api-key': process.env.S2_API_KEY || '' }
                }).catch(e => null);

                if (searchRes && searchRes.data && searchRes.data.data && searchRes.data.data.length > 0) {
                    authorIdToFetch = searchRes.data.data.at(0).authorId;
                }
            }

            
            if (authorIdToFetch) {
                const resData = await axios.get(`https://api.semanticscholar.org/graph/v1/author/${authorIdToFetch}`, {
                    params: { fields: 'name,citationCount,hIndex,paperCount,url,papers.title,papers.year,papers.venue,papers.citationCount,papers.fieldsOfStudy,papers.authors,papers.url' },
                    headers: { 'x-api-key': process.env.S2_API_KEY || '' }
                }).catch(e => null);
                
                if (resData && resData.data) {
                    s2AuthorData = resData.data;
                    s2AuthorData.primaryField = extractTopField(s2AuthorData.papers);
                }
            }

            // (Collaborators)
            let collaborators = [];
            if (s2AuthorData && s2AuthorData.papers) {
                const collabMap = new Map();
                s2AuthorData.papers.forEach(p => {
                    if(p.authors) {
                        p.authors.forEach(a => {
                            // Don't count the researcher themselves
                            if (a.authorId !== s2AuthorData.authorId && a.name) {
                                // Use ID as key to be accurate
                                if (!collabMap.has(a.authorId)) {
                                    collabMap.set(a.authorId, { name: a.name, id: a.authorId, count: 0 });
                                }
                                collabMap.get(a.authorId).count++;
                            }
                        });
                    }
                });
                
                collaborators = Array.from(collabMap.values())
                    .sort((a, b) => b.count - a.count)
                    .slice(0, 10); // Return top 10
            }

            res.json({ local: localData, author: s2AuthorData, collaborators: collaborators });
            
        } catch (e) {
            console.error("Analyze Error:", e.message);
            res.json({ local: localData, author: null, collaborators: [] });
        }
    });
});






// Get Filters & Map Status
app.get('/api/job-filters', (req, res) => {
    db.all("SELECT DISTINCT country, country_code FROM jobs", [], (err, countries) => {
        db.all("SELECT DISTINCT company FROM jobs", [], (err, companies) => {
            db.all("SELECT DISTINCT track FROM jobs", [], (err, tracks) => {
                // Map needs to know which countries have ANY jobs to color them blue initially
                const activeCodes = countries.map(c => c.country_code);
                res.json({ 
                    countries, 
                    companies: companies.map(c => c.company), 
                    tracks: tracks.map(t => t.track),
                    activeCodes 
                });
            });
        });
    });
});

// Get Jobs with Multi-Selection Logic
app.post('/api/jobs/query', (req, res) => {
    // We use POST to easily send arrays (for multi-select)
    const { countries, track, company, q } = req.body; // countries is an Array ['US', 'EG']

    let sql = "SELECT * FROM jobs WHERE 1=1";
    let params = [];

    // Multi-Country Filter
    if (countries && countries.length > 0 && !countries.includes('All')) {
        const placeholders = countries.map(() => '?').join(',');
        sql += ` AND country_code IN (${placeholders})`;
        params.push(...countries);
    }

    if (track && track !== 'All') {
        sql += " AND track = ?";
        params.push(track);
    }
    if (company && company !== 'All') {
        sql += " AND company = ?";
        params.push(company);
    }
    if (q) {
        sql += " AND (title LIKE ? OR description LIKE ?)";
        params.push(`%${q}%`, `%${q}%`);
    }

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Enhance rows with Logo URL
        const enhanced = rows.map(r => ({
            ...r,
            logo: `https://logo.clearbit.com/${r.company_domain}`
        }));
        res.json(enhanced);
    });
});

/**
 * API: Submit Application
 * Receives JSON data and stores it in memory.
 */
app.post('/api/apply', upload.single('cv'), (req, res) => {
    const { jobId, applicantName, applicantEmail, applicantPhone } = req.body;
    
    // Construct the public URL path for the file
    const cvPath = req.file ? `/uploads/jobs/${jobId}/${req.file.filename}` : null;

    const sql = "INSERT INTO applications (jobId, applicantName, applicantEmail, applicantPhone, cvPath) VALUES (?, ?, ?, ?, ?)";
    db.run(sql, [jobId, applicantName, applicantEmail, applicantPhone, cvPath], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Application failed" });
        }
        res.json({ success: true, message: "Application submitted successfully." });
    });
});


// ================================================================
//  SECTION 2: ACADEMIC SCANNER API (Researcher Analysis)
// ================================================================

/**
 * API: Search Researchers
 * Wraps Semantic Scholar API
 */
app.get('/api/search', async (req, res) => {
    if (!req.query.q) return res.status(400).json({ error: "Query required" });
    try {
        const response = await axios.get(`https://api.semanticscholar.org/graph/v1/author/search`, {
            params: { 
                query: req.query.q, 
                limit: 15, 
                fields: 'authorId,name,hIndex,paperCount,citationCount,papers.fieldsOfStudy' 
            },
            headers: { 'x-api-key': process.env.S2_API_KEY || '' }
        });

        const processed = (response.data.data || []).map(author => ({
            ...author,
            primaryField: extractTopField(author.papers)
        }));

        res.json(processed);
    } catch (e) {
        console.error("S2 Search Error:", e.message);
        res.status(500).json({ error: "Search Service Unavailable" });
    }
});

/**
 * API: Deep Analyze Researcher
 * Fetches papers from S2, then sends data to Gemini AI for profiling.
 */
app.post('/api/analyze', async (req, res) => {
    const { authorId, userDescription } = req.body;
    if (!authorId) return res.status(400).send("Target ID Required");

    try {
        // 1. Fetch Author Data from S2
        const resData = await axios.get(`https://api.semanticscholar.org/graph/v1/author/${authorId}`, {
            params: { 
                fields: 'name,citationCount,hIndex,paperCount,url,papers.title,papers.year,papers.venue,papers.citationCount,papers.fieldsOfStudy,papers.authors,papers.url' 
            },
            headers: { 'x-api-key': process.env.S2_API_KEY || '' }
        });

        const author = resData.data;
        author.primaryField = extractTopField(author.papers);

        // 2. Prepare Data for AI
        const keyPapers = author.papers
            .sort((a,b) => (b.citationCount || 0) - (a.citationCount || 0))
            .slice(0, 30) // Top 30 papers
            .map(p => `[${p.year}] "${p.title}" (Citations: ${p.citationCount})`)
            .join('\n');

        // 3. Calculate Collaborations
        const collaborators = {};
        if(author.papers) {
            author.papers.forEach(p => {
                if(p.authors) p.authors.forEach(a => {
                    if (a.authorId !== authorId && a.name) {
                        collaborators[a.name] = (collaborators[a.name] || 0) + 1;
                    }
                });
            });
        }
        const topCollabs = Object.entries(collaborators)
            .sort((a,b) => b[1]-a[1])
            .slice(0, 8);

        // 4. Generate AI Prompt
        const prompt = `
            Act as an Academic Profiler.
            TARGET: ${author.name}. FIELD: ${author.primaryField}.
            STATS: H-Index: ${author.hIndex}, Citations: ${author.citationCount}.
            TOP PAPERS:
            ${keyPapers}

            USER CONTEXT: "${userDescription || 'General Academic Assessment'}".

            TASK:
            1. Analyze the career trajectory & specific expertise.
            2. Calculate a "Relevance Match Score" (0-100) based on the user's context.
            3. Identify key technologies or methodologies used.
            
            OUTPUT JSON ONLY (No Markdown):
            {
                "full_report": "3 paragraphs analysis.",
                "match_score": 85,
                "match_reason": "One sentence explaining the score.",
                "key_technologies": ["Tech1", "Tech2", "Tech3"]
            }
        `;

        // 5. Call Gemini
        const aiResult = await model.generateContent(prompt);
        const text = aiResult.response.text().replace(/```json/g, '').replace(/```/g, '').trim();
        
        let analysisData;
        try { 
            analysisData = JSON.parse(text); 
        } catch (e) { 
            analysisData = { full_report: text, match_score: 0, key_technologies: [] }; 
        }

        res.json({ author, analysis: analysisData, collaborators: topCollabs });

    } catch (e) {
        console.error("Analysis Error:", e);
        res.status(500).json({ error: "Analysis Failed" });
    }
});


// ================================================================
//  SECTION 3: TOPIC EXPLORER API
// ================================================================

/**
 * API: Explore Idea
 * AI converts idea to keywords -> Parallel Search -> Ranking Algorithm
 */
app.post('/api/explore', async (req, res) => {
    const { idea, minYear } = req.body;
    
    try {
        // 1. AI: Convert Idea to Keywords
        const keywordPrompt = `
            Act as a Research Librarian. Convert this research idea into 4 distinct, specific academic search queries.
            Idea: "${idea}"
            Output ONLY a JSON array of strings. Example: ["Deep Learning in MRI", "CNN Tumor Detection"]
        `;
        
        const aiKeywords = await model.generateContent(keywordPrompt);
        const text = aiKeywords.response.text().replace(/```json/g, '').replace(/```/g, '').trim();
        let queries = [];
        try { queries = JSON.parse(text); } catch(e) { queries = [idea]; }

        // 2. Parallel Search on S2
        const searchPromises = queries.map(q => 
            axios.get(`https://api.semanticscholar.org/graph/v1/paper/search`, {
                params: { 
                    query: q, 
                    limit: 20, 
                    fields: 'title,year,citationCount,authors.name,authors.authorId,authors.paperCount,authors.hIndex,authors.citationCount' 
                },
                headers: { 'x-api-key': process.env.S2_API_KEY || '' }
            }).catch(e => ({ data: { data: [] } }))
        );

        const results = await Promise.all(searchPromises);
        
        // 3. Process & Rank Authors
        const authorMap = {};

        results.forEach(response => {
            const papers = response.data.data || [];
            papers.forEach(paper => {
                if (minYear && paper.year < minYear) return;

                paper.authors.forEach(auth => {
                    if (!auth.authorId) return;

                    if (!authorMap[auth.authorId]) {
                        authorMap[auth.authorId] = {
                            id: auth.authorId,
                            name: auth.name,
                            hIndex: auth.hIndex || 0,
                            citationCount: auth.citationCount || 0,
                            topic_papers: 0,
                            topic_citations: 0,
                            last_active: 0
                        };
                    }

                    const stats = authorMap[auth.authorId];
                    stats.topic_papers += 1;
                    stats.topic_citations += (paper.citationCount || 0);
                    if (paper.year > stats.last_active) stats.last_active = paper.year;
                });
            });
        });

        // 4. Scoring Algorithm
        let leaderboard = Object.values(authorMap);
        // Score = (Topic Papers * 20) + (Topic Citations * 1) + (H-Index * 0.5)
        leaderboard.forEach(a => {
            a.score = (a.topic_papers * 20) + (a.topic_citations * 1) + (a.hIndex * 0.5);
        });

        // Sort descending
        leaderboard.sort((a, b) => b.score - a.score);

        res.json({ 
            queries: queries, 
            authors: leaderboard.slice(0, 50) 
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Exploration Failed" });
    }
});


// ================================================================
//  SECTION 4: HOT TOPICS API
// ================================================================


app.get('/api/hottopics', (req, res) => {
    const sql = "SELECT * FROM hot_topics ORDER BY priority DESC";
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows); 
    });
});


app.post('/api/hottopics/add', isAdmin, (req, res) => {
    const { title, description, field, type, status, priority, link } = req.body;
    const sql = `INSERT INTO hot_topics (title, description, field, type, status, priority, link) VALUES (?,?,?,?,?,?,?)`;
    db.run(sql, [title, description, field, type, status, priority || 0, link], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});


app.delete('/api/hottopics/:id', isAdmin, (req, res) => {
    db.run("DELETE FROM hot_topics WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});



// Middleware to extract user from token (Reuse your isAdmin logic or make a generic one)
const isAuthenticated = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: "Access Denied" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(400).json({ error: "Invalid token." });
    }
};

app.post('/api/jobs/add', isAuthenticated, (req, res) => {
    const { title, company, country, country_code, track, type, seniority, description, requirements, salary, apply_link } = req.body;
    const owner_id = req.user.id; // From Token

    const sql = "INSERT INTO jobs (owner_id, title, company, country, country_code, track, type, seniority, description, requirements, salary, apply_link) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
    
    db.run(sql, [owner_id, title, company, country, country_code, track, type, seniority, description, requirements, salary, apply_link], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, jobId: this.lastID });
    });
});

// ================================================================
//  SECTION 5: AUTHENTICATION & USERS
// ================================================================

// Register
// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    
    // companies need acceptance or permitions
    // (isApproved = 1 , waiting = 0)
    const isApproved = (role === 'user' || role === 'admin') ? 1 : 0;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run("INSERT INTO users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
            [name, email, hashedPassword, role, isApproved],
            function(err) {
                if (err) {
                    console.error("DB Register Error:", err.message); 
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: "Email already exists" });
                    }
                    return res.status(500).json({ error: "Database error during registration" });
                }


                if (isApproved === 0) {
                    res.json({ success: true, message: "Account created. Waiting for Admin approval." });
                } else {
                    res.json({ success: true, message: "Registration successful. You can login now." });
                }
            }
        );
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Server error" });
    }
});


// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials" });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });

        if (user.is_approved === 0) {
            return res.status(403).json({ error: "Your account is pending Admin approval." });
        }

        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });

        // tokens in cookies
        res.cookie('auth_token', token, {
            httpOnly: true, //   لحد ما نظبط حوار ال testing  XSS
            secure: false,  // خليها true في حالة الـ HTTPS (Production)
            maxAge: 24 * 60 * 60 * 1000 // one day
        });

        res.json({ 
            success: true, 
            user: { id: user.id, name: user.name, role: user.role } 
        });
    });
});


app.get('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true, message: "Logged out" });
});


// Add New Job (Company/Admin Only)
app.post('/api/jobs/add', (req, res) => {
    const { title, company, country, country_code, track, type, seniority, description, requirements, salary } = req.body;
    
    const sql = "INSERT INTO jobs (title, company, country, country_code, track, type, seniority, description, requirements, salary) VALUES (?,?,?,?,?,?,?,?,?,?)";
    db.run(sql, [title, company, country, country_code, track, type, seniority, description, requirements, salary], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, jobId: this.lastID }); //success: true
    });
});


// GET Applicants for a specific job (Secured)
app.get('/api/jobs/:id/applicants', isAdmin, (req, res) => { 
    // Note: isAdmin here checks if user is logged in. 
    // Ideally, create a specific middleware 'isJobOwner' as discussed before.
    // For now, assuming 'isAdmin' simply verifies a valid JWT token exists.
    
    const jobId = req.params.id;
    const userId = req.user.id; // From the token
    const userRole = req.user.role;

    // 1. Verify this user owns the job
    db.get("SELECT owner_id, title FROM jobs WHERE id = ?", [jobId], (err, job) => {
        if (err || !job) return res.status(404).json({ error: "Job not found" });

        // Allow if user is the Owner OR an Admin
        if (job.owner_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ error: "Access Denied. You do not own this job post." });
        }

        // 2. Fetch Applicants
        const sql = `SELECT id, applicantName, applicantEmail, applicantPhone, cvPath, timestamp FROM applications WHERE jobId = ? ORDER BY timestamp DESC`;
        
        db.all(sql, [jobId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});


app.delete('/api/jobs/:id', isAuthenticated, (req, res) => {
    const jobId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // First check if user owns the job or is admin
    db.get("SELECT owner_id FROM jobs WHERE id = ?", [jobId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "Job not found" });

        if (row.owner_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ error: "Unauthorized" });
        }

        // 1. Delete Job Entry
        db.run("DELETE FROM jobs WHERE id = ?", [jobId], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            // 2. Delete Applications Entry
            db.run("DELETE FROM applications WHERE jobId = ?", [jobId]);

            // 3. Delete CV Folder (Optional, but keeps server clean)
            const jobFolder = path.join(__dirname, `public/uploads/jobs/${jobId}`);
            if (fs.existsSync(jobFolder)) {
                fs.rm(jobFolder, { recursive: true, force: true }, () => {});
            }

            res.json({ success: true });
        });
    });
});


app.get('/api/admin/pending-users', (req, res) => {
    db.all("SELECT id, name, email, role FROM users WHERE is_approved = 0", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});


app.post('/api/admin/approve-user', (req, res) => {
    const { userId } = req.body;
    db.run("UPDATE users SET is_approved = 1 WHERE id = ?", [userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});


// ================================================================
//  SECTION 6: COMPANIES DIRECTORY API (REVISED)
// ================================================================

// API: Upload Companies
app.post('/api/admin/upload-companies', isAdmin, uploadTemp.single('file'), (req, res) => {
    if (!req.file || !req.file.buffer) return res.status(400).json({error: "No file uploaded"});
    
    const clearDb = req.body.clear_db === 'true';

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const companiesMap = {};

        workbook.SheetNames.forEach(sheetName => {
            const sheet = workbook.Sheets[sheetName];
            
            // 1. Convert to JSON for data
            const rows = xlsx.utils.sheet_to_json(sheet);
            
            // 2. MINE HYPERLINKS (The Fix)
            // We verify which row each link belongs to
            const rowLinks = {}; // Map: RowIndex -> { website: '', linkedin: '' }
            
            // Parse the range (e.g., A1:Z100)
            const range = xlsx.utils.decode_range(sheet['!ref']);
            
            // Loop through every cell to find hidden links
            for (let R = range.s.r; R <= range.e.r; ++R) {
                for (let C = range.s.c; C <= range.e.c; ++C) {
                    const cellRef = xlsx.utils.encode_cell({c: C, r: R});
                    const cell = sheet[cellRef];
                    
                    // Check if cell has a Hyperlink (.l)
                    if (cell && cell.l && cell.l.Target) {
                        const url = cell.l.Target;
                        const rowIndex = R - 1; // Adjust for header row (approximate)

                        if (!rowLinks[rowIndex]) rowLinks[rowIndex] = { website: '', linkedin: '' };
                        
                        if (url.includes('linkedin.com')) {
                            rowLinks[rowIndex].linkedin = url;
                        } else if (url.startsWith('http') || url.startsWith('www')) {
                            // Avoid setting website if we already found one in this row
                            if (!rowLinks[rowIndex].website) rowLinks[rowIndex].website = url;
                        }
                    }
                }
            }

            const region = sheetName.trim(); 

            // 3. Process Rows
            rows.forEach((row, index) => {
                const name = extractData(row, 'name');
                if (!name) return;

                const nameKey = name.toLowerCase().trim();
                
                // DATA EXTRACTION
                const category = extractData(row, 'category') || 'General';
                const industry = extractData(row, 'industry');
                const size = extractData(row, 'size') || 'N/A';
                const presence = extractData(row, 'presence');
                
                // LINK STRATEGY: 
                // Priority 1: Hidden Excel Hyperlink (mined above)
                // Priority 2: Visible Text in the cell (extracted via helper)
                let mined = rowLinks[index] || {};
                
                let website = mined.website || extractData(row, 'website');
                let linkedin = mined.linkedin || extractData(row, 'linkedin');

                // Fallback: Scan text in row if no link found yet
                if (!website && !linkedin) {
                    Object.values(row).forEach(val => {
                        const sVal = String(val).toLowerCase();
                        if (sVal.includes('http') || sVal.includes('www.')) {
                            if (sVal.includes('linkedin')) linkedin = String(val);
                            else website = String(val);
                        }
                    });
                }

                // LOCATION PARSING
                let rawLocation = extractData(row, 'location') || 'Unknown';
                let country = rawLocation;
                let state = null;
                let city = null;

                if (rawLocation.includes('(')) {
                    const parts = rawLocation.split('(');
                    country = parts[0].trim();
                    const sub = parts[1].replace(')', '').trim();
                    
                    if (region.toUpperCase().includes('USA') || region.toUpperCase().includes('AMERICA')) {
                        country = "United States";
                        state = parts[0].trim();
                        city = sub;
                    } else {
                        city = sub;
                    }
                } else if (region.toUpperCase().includes('USA')) {
                    country = "United States";
                    state = rawLocation;
                }

                // GROUPING
                if (!companiesMap[nameKey]) {
                    companiesMap[nameKey] = {
                        name: name.trim(),
                        category: category,
                        industry: industry,
                        size: size,
                        website: website,
                        linkedin: linkedin,
                        hq_country: country,
                        branches: []
                    };
                }

                const entry = companiesMap[nameKey];

                // Update info if better data found
                if (website && (!entry.website || entry.website.length < 5)) entry.website = website;
                if (linkedin && (!entry.linkedin || entry.linkedin.length < 5)) entry.linkedin = linkedin;
                if (size && size !== 'N/A' && entry.size === 'N/A') entry.size = size;

                // Add Branch
                const isDup = entry.branches.some(b => b.country === country && b.state === state);
                if (!isDup) {
                    entry.branches.push({ region, country, state, city, presence });
                }
            });
        });

        // Database Save
        db.serialize(() => {
            if (clearDb) db.run("DELETE FROM companies");
            
            db.run(`CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT, category TEXT, industry TEXT, size TEXT, 
                website TEXT, linkedin TEXT, branches TEXT, hq_country TEXT
            )`);

            const stmt = db.prepare(`INSERT INTO companies (name, category, industry, size, website, linkedin, branches, hq_country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
            let count = 0;
            
            Object.values(companiesMap).forEach(c => {
                stmt.run(c.name, c.category, c.industry, c.size, c.website, c.linkedin, JSON.stringify(c.branches), c.hq_country);
                count++;
            });
            stmt.finalize();
            res.json({ success: true, message: `Processed ${count} companies.` });
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Upload failed: " + err.message });
    }
});

// 2. Search Companies (Matches ANY branch)
app.get('/api/companies', (req, res) => {
    const { q, country, category } = req.query; 

    let sql = "SELECT * FROM companies WHERE 1=1";
    let params = [];

    if (q) {
        sql += " AND (name LIKE ? OR industry LIKE ?)";
        params.push(`%${q}%`, `%${q}%`);
    }

    if (category && category !== 'All') {
        sql += " AND category = ?";
        params.push(category);
    }

    if (country && country !== 'All') {
        const list = country.split(',');
        // This Logic checks if the country string exists ANYWHERE in the JSON branches
        // Effectively treating a branch in Egypt as equal to a company HQ'd in Egypt
        const likeClauses = list.map(() => "branches LIKE ?").join(' OR ');
        sql += ` AND (${likeClauses})`;
        list.forEach(c => params.push(`%${c}%`)); 
    }

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const enhanced = rows.map(r => ({
            ...r,
            // Fallback logo generator
            logo: `https://logo.clearbit.com/${r.name.replace(/[\s,.]+/g, '').toLowerCase()}.com`,
            branches: JSON.parse(r.branches || '[]')
        }));
        res.json(enhanced);
    });
});

// 3. Get Filters (Extracts unique countries from JSON)
app.get('/api/companies/filters', (req, res) => {
    db.all("SELECT branches, category FROM companies", [], (err, rows) => {
        const countries = new Set();
        const categories = new Set();
        
        rows.forEach(r => {
            if(r.category) categories.add(r.category);
            try {
                const b = JSON.parse(r.branches);
                b.forEach(branch => {
                    if(branch.country) countries.add(branch.country);
                });
            } catch(e) {}
        });

        res.json({
            countries: Array.from(countries).sort(),
            categories: Array.from(categories).sort()
        });
    });
});





// ================================================================
//  HELPERS & STARTUP
// ================================================================

function extractData(row, type) {
    const keywords = {
        name: ['companyname', 'company', 'name', 'entity'],
        website: ['website', 'web', 'url', 'companylink', 'link', 'site', 'homepage'],
        linkedin: ['linkedin', 'profile'],
        size: ['size', 'employee', 'staff', 'number'],
        category: ['category', 'cat', 'sector'],
        industry: ['industry', 'focus', 'vlsi', 'specialization'],
        presence: ['presence', 'type', 'status'],
        location: ['country', 'state', 'location', 'region', 'hq']
    };

    const targetKeys = keywords[type] || [];
    const rowKeys = Object.keys(row);
    
    // Find matching key
    let matchKey = rowKeys.find(key => 
        targetKeys.some(k => key.toLowerCase().replace(/[^a-z]/g, '').includes(k))
    );

    let value = matchKey ? row[matchKey] : null;

    if (value && typeof value === 'string') return value.trim();
    return '';
}

function extractTopField(papers) {
    if (!papers || papers.length === 0) return "General Science";
    const fieldCounts = {};
    papers.forEach(p => {
        if (p.fieldsOfStudy) {
            p.fieldsOfStudy.forEach(field => {
                fieldCounts[field] = (fieldCounts[field] || 0) + 1;
            });
        }
    });
    const sortedFields = Object.entries(fieldCounts).sort((a, b) => b[1] - a[1]);
    return sortedFields.length > 0 ? sortedFields[0][0] : "Multidisciplinary";
}



function getFuzzyValue(row, keywords) {
    const keys = Object.keys(row);
    // Find a key that contains one of the keywords (case insensitive)
    const match = keys.find(key => 
        keywords.some(word => key.toLowerCase().replace(/[^a-z]/g, '').includes(word))
    );
    return match ? row[match] : '';
}



app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;