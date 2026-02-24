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

// Multer Storage Configuration (Now using Memory Storage for Supabase Uploads)
// Ensure uploads directory exists comment kept for context, but Supabase handles storage now
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
const uploadTemp = multer({ storage: multer.memoryStorage() });

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// --- DATABASE INITIALIZATION (Supabase) ---
const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

console.log("Connected to Supabase database.");

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
    async (req, res) => {

    if (!req.file || !req.file.buffer) {
        return res.status(400).json({error: "No file uploaded or invalid format"});
    }
    
    const clearDb = req.body.clear_db === 'true';

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });

        if (clearDb) {
            await supabase.from('academic_researchers').delete().neq('id', 0);
        }

        let researchersToInsert = [];
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
                
                researchersToInsert.push({
                    name, affiliation: affil, main_topic: topicToSave, subtopics, scholar_id
                });
            }
        });
        
        // Batch Insert to Supabase
        if (researchersToInsert.length > 0) {
            await supabase.from('academic_researchers').insert(researchersToInsert);
        }
        
        res.json({success: true, message: `Database synced! Added ${researchersToInsert.length} researchers.`});

    } catch (err) {
        console.error("Excel Parsing Error:", err);
        res.status(500).json({error: "Failed to parse file."});
    }
});

// 2. Fetch distinct Main Topics for the dropdown
app.get('/api/local-researchers/main-topics', async (req, res) => {
    const { data, error } = await supabase.from('academic_researchers').select('main_topic');
    if (error) return res.status(500).json({error: error.message});
    
    // Get unique non-null topics
    const topics = [...new Set(data.map(r => r.main_topic).filter(t => t && t.trim() !== ''))];
    res.json(topics);
});

// 3. New Specific Filter Endpoint
app.get('/api/local-researchers/filter', async (req, res) => {
    const { main_topic, subtopic, university, researcher } = req.query;
    
    let query = supabase.from('academic_researchers').select('*');
    
    if (main_topic) query = query.eq('main_topic', main_topic);
    if (subtopic) query = query.ilike('subtopics', `%${subtopic}%`);
    if (university) query = query.ilike('affiliation', `%${university}%`);
    if (researcher) query = query.ilike('name', `%${researcher}%`);
    
    // بص لو حد هيعدل بعدي في كام نوت مهمه لحاجات مسحتهم و حاجات كان لازم تتضاف 
    // الحته دي كنت حاططها علشان مبعتش كل حاجه من الداتا بيز للفرونت مباشر 
    // بس كان فيه مشكلة اني هبقي مضطر احسب حسابات الداش بورد في الباك اند و ابعتها للفرونت فانا مش هعمل كده
    // طبعا المفروض اني كنت اخطط لده من الاول بس ما علينا لو لقيت نفسك مضطر ترجع لهنا يعني و تقلل الي بيتبعت للفرونت 
    //عدل بس هنا و خد بالك من تحديث الداش بورد  في الصفحة دي 
    // REMOVED: sql += ` LIMIT 150`;  <-- DELETE THIS LINE
    // If you really want a safety cap, make it huge like 10000
    // sql += ` LIMIT 10000`; 

    const { data: rows, error } = await query;
    if (error) return res.status(500).json({error: error.message});
    res.json(rows);
});

// 4. Detailed Analyze (Smart ID or Name Search)
app.post('/api/local-researchers/analyze', async (req, res) => {
    const id = req.body.id;
    
    const { data: localData, error } = await supabase.from('academic_researchers').select('*').eq('id', id).single();
    
    if (error || !localData) {
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


// Get Filters & Map Status
app.get('/api/job-filters', async (req, res) => {
    const { data: rows, error } = await supabase.from('jobs').select('country, country_code, company, track');
    if (error) return res.status(500).json({ error: error.message });

    const countriesSet = new Map();
    const companies = new Set();
    const tracks = new Set();
    const activeCodes = new Set();

    rows.forEach(r => {
        if (r.country && r.country_code) {
            countriesSet.set(r.country_code, { country: r.country, country_code: r.country_code });
            activeCodes.add(r.country_code);
        }
        if (r.company) companies.add(r.company);
        if (r.track) tracks.add(r.track);
    });

    res.json({ 
        countries: Array.from(countriesSet.values()), 
        companies: Array.from(companies), 
        tracks: Array.from(tracks),
        activeCodes: Array.from(activeCodes) 
    });
});

// Get Jobs with Multi-Selection Logic
app.post('/api/jobs/query', async (req, res) => {
    // We use POST to easily send arrays (for multi-select)
    const { countries, track, company, q } = req.body; // countries is an Array ['US', 'EG']

    let query = supabase.from('jobs').select('*');

    // Multi-Country Filter
    if (countries && countries.length > 0 && !countries.includes('All')) {
        query = query.in('country_code', countries);
    }

    if (track && track !== 'All') {
        query = query.eq('track', track);
    }
    if (company && company !== 'All') {
        query = query.eq('company', company);
    }
    if (q) {
        query = query.or(`title.ilike.%${q}%,description.ilike.%${q}%`);
    }

    const { data: rows, error } = await query;
    
    if (error) return res.status(500).json({ error: error.message });

    // Enhance rows with Logo URL
    const enhanced = rows.map(r => ({
        ...r,
        logo: `https://logo.clearbit.com/${r.company_domain}`
    }));
    res.json(enhanced);
});

/**
 * API: Submit Application
 * Receives JSON data and stores it in memory.
 */
app.post('/api/apply', upload.single('cv'), async (req, res) => {
    const { jobId, applicantName, applicantEmail, applicantPhone } = req.body;
    
    let cvPath = null;
    
    // Construct the public URL path for the file via Supabase Storage
    if (req.file) {
        const fileExt = req.file.originalname.split('.').pop();
        const fileName = `${jobId}/${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;

        const { data: uploadData, error: uploadError } = await supabase.storage
            .from('cv-uploads') // Ensure this bucket exists in Supabase
            .upload(fileName, req.file.buffer, {
                contentType: req.file.mimetype
            });

        if (uploadError) {
            console.error(uploadError);
            return res.status(500).json({ error: "File upload failed" });
        }
        
        const { data: publicUrlData } = supabase.storage
            .from('cv-uploads')
            .getPublicUrl(fileName);
            
        cvPath = publicUrlData.publicUrl;
    }

    const { error } = await supabase
        .from('applications')
        .insert([{ jobId, applicantName, applicantEmail, applicantPhone, cvPath }]);

    if (error) {
        console.error(error);
        return res.status(500).json({ error: "Application failed" });
    }
    res.json({ success: true, message: "Application submitted successfully." });
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

app.get('/api/hottopics', async (req, res) => {
    const { data, error } = await supabase
        .from('hot_topics')
        .select('*')
        .order('priority', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/hottopics/add', isAdmin, async (req, res) => {
    const { title, description, field, type, status, priority, link } = req.body;
    
    const { data, error } = await supabase
        .from('hot_topics')
        .insert([{ title, description, field, type, status, priority: priority || 0, link }])
        .select()
        .single();
        
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, id: data.id });
});

app.delete('/api/hottopics/:id', isAdmin, async (req, res) => {
    const { error } = await supabase.from('hot_topics').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
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

app.post('/api/jobs/add', isAuthenticated, async (req, res) => {
    const { title, company, country, country_code, track, type, seniority, description, requirements, salary, apply_link } = req.body;
    const owner_id = req.user.id; // From Token

    const { data, error } = await supabase
        .from('jobs')
        .insert([{ owner_id, title, company, country, country_code, track, type, seniority, description, requirements, salary, apply_link }])
        .select()
        .single();
        
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, jobId: data.id });
});

// ================================================================
//  SECTION 5: AUTHENTICATION & USERS
// ================================================================

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    
    // companies need acceptance or permitions
    // (isApproved = 1 , waiting = 0)
    const isApproved = (role === 'user' || role === 'admin') ? 1 : 0;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const { error } = await supabase
            .from('users')
            .insert([{ name, email, password: hashedPassword, role, is_approved: isApproved }]);

        if (error) {
            console.error("DB Register Error:", error.message); 
            // Postgres unique violation code is 23505
            if (error.code === '23505') {
                return res.status(400).json({ error: "Email already exists" });
            }
            return res.status(500).json({ error: "Database error during registration" });
        }

        if (isApproved === 0) {
            res.json({ success: true, message: "Account created. Waiting for Admin approval." });
        } else {
            res.json({ success: true, message: "Registration successful. You can login now." });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Server error" });
    }
});


// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    if (error || !user) return res.status(400).json({ error: "Invalid credentials" });
    
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


app.get('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true, message: "Logged out" });
});


// Add New Job (Company/Admin Only)
// (Note: There was a duplicate definition of this route in SQLite version, mapped to the same behavior)
app.post('/api/jobs/add', async (req, res) => {
    const { title, company, country, country_code, track, type, seniority, description, requirements, salary } = req.body;
    
    const { data, error } = await supabase
        .from('jobs')
        .insert([{ title, company, country, country_code, track, type, seniority, description, requirements, salary }])
        .select()
        .single();
        
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, jobId: data.id }); 
});


// GET Applicants for a specific job (Secured)
app.get('/api/jobs/:id/applicants', isAdmin, async (req, res) => { 
    // Note: isAdmin here checks if user is logged in. 
    // Ideally, create a specific middleware 'isJobOwner' as discussed before.
    // For now, assuming 'isAdmin' simply verifies a valid JWT token exists.
    
    const jobId = req.params.id;
    const userId = req.user.id; // From the token
    const userRole = req.user.role;

    // 1. Verify this user owns the job
    const { data: job, error: jobError } = await supabase
        .from('jobs')
        .select('owner_id, title')
        .eq('id', jobId)
        .single();

    if (jobError || !job) return res.status(404).json({ error: "Job not found" });

    // Allow if user is the Owner OR an Admin
    if (job.owner_id !== userId && userRole !== 'admin') {
        return res.status(403).json({ error: "Access Denied. You do not own this job post." });
    }

    // 2. Fetch Applicants
    const { data: rows, error } = await supabase
        .from('applications')
        .select('id, applicantName, applicantEmail, applicantPhone, cvPath, timestamp')
        .eq('jobId', jobId)
        .order('timestamp', { ascending: false });
        
    if (error) return res.status(500).json({ error: error.message });
    res.json(rows);
});


app.delete('/api/jobs/:id', isAuthenticated, async (req, res) => {
    const jobId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // First check if user owns the job or is admin
    const { data: row, error: jobError } = await supabase
        .from('jobs')
        .select('owner_id')
        .eq('id', jobId)
        .single();

    if (jobError || !row) return res.status(404).json({ error: "Job not found" });

    if (row.owner_id !== userId && userRole !== 'admin') {
        return res.status(403).json({ error: "Unauthorized" });
    }

    // 1. Delete Job Entry
    const { error: delJobError } = await supabase.from('jobs').delete().eq('id', jobId);
    if (delJobError) return res.status(500).json({ error: delJobError.message });

    // 2. Delete Applications Entry
    await supabase.from('applications').delete().eq('jobId', jobId);

    // 3. Delete CV Folder (Optional, but keeps server clean)
    // Note: Since we are using Supabase storage, folder deletion logic is commented out here to preserve exact structural comments.
    // const jobFolder = path.join(__dirname, `public/uploads/jobs/${jobId}`);
    // if (fs.existsSync(jobFolder)) {
    //     fs.rm(jobFolder, { recursive: true, force: true }, () => {});
    // }

    res.json({ success: true });
});


app.get('/api/admin/pending-users', async (req, res) => {
    const { data: rows, error } = await supabase
        .from('users')
        .select('id, name, email, role')
        .eq('is_approved', 0);
        
    if (error) return res.status(500).json({ error: error.message });
    res.json(rows);
});


app.post('/api/admin/approve-user', async (req, res) => {
    const { userId } = req.body;
    
    const { error } = await supabase
        .from('users')
        .update({ is_approved: 1 })
        .eq('id', userId);
        
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});


// ================================================================
//  SECTION 6: COMPANIES DIRECTORY API (REVISED)
// ================================================================

// API: Upload Companies
app.post('/api/admin/upload-companies', isAdmin, uploadTemp.single('file'), async (req, res) => {
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

        // Database Save Process (Supabase)
        if (clearDb) {
            await supabase.from('companies').delete().neq('id', 0);
        }

        const companiesToInsert = Object.values(companiesMap).map(c => ({
            name: c.name, 
            category: c.category, 
            industry: c.industry, 
            size: c.size, 
            website: c.website, 
            linkedin: c.linkedin, 
            branches: JSON.stringify(c.branches), 
            hq_country: c.hq_country
        }));

        if (companiesToInsert.length > 0) {
            await supabase.from('companies').insert(companiesToInsert);
        }

        res.json({ success: true, message: `Processed ${companiesToInsert.length} companies.` });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Upload failed: " + err.message });
    }
});

// 2. Search Companies (Matches ANY branch)
app.get('/api/companies', async (req, res) => {
    const { q, country, category } = req.query; 

    let query = supabase.from('companies').select('*');

    if (category && category !== 'All') {
        query = query.eq('category', category);
    }
    
    if (q) {
        query = query.or(`name.ilike.%${q}%,industry.ilike.%${q}%`);
    }

    const { data: rows, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    let finalRows = rows;

    if (country && country !== 'All') {
        const list = country.split(',');
        // This Logic checks if the country string exists ANYWHERE in the JSON branches
        // Effectively treating a branch in Egypt as equal to a company HQ'd in Egypt
        finalRows = rows.filter(r => {
            const bStr = r.branches || '';
            return list.some(c => bStr.includes(c));
        });
    }

    const enhanced = finalRows.map(r => ({
        ...r,
        // Fallback logo generator
        logo: `https://logo.clearbit.com/${r.name.replace(/[\s,.]+/g, '').toLowerCase()}.com`,
        branches: JSON.parse(r.branches || '[]')
    }));
    
    res.json(enhanced);
});

// 3. Get Filters (Extracts unique countries from JSON)
app.get('/api/companies/filters', async (req, res) => {
    const { data: rows, error } = await supabase.from('companies').select('branches, category');
    
    if (error) return res.status(500).json({ error: error.message });

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

// 1. Serve HTML Pages
app.get('/team', (req, res) => res.sendFile(path.join(__dirname, 'public', 'team.html')));
app.get('/grad-form', (req, res) => res.sendFile(path.join(__dirname, 'public', 'grad-form.html')));
app.get('/grad-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'grad-dashboard.html')));

// 2. API: Submit Project
app.post('/api/grad-projects/submit', async (req, res) => {
    const {
        studentName, email, phone, university, faculty, major,
        supervisor, coSupervisor, isSponsored, sponsorCompany,
        companyMentor, gradYear, domains, projectTitle, peersCount, docLink
    } = req.body;

    // Prepare data for Supabase
    const { data, error } = await supabase
        .from('graduation_projects')
        .insert([{
            student_name: studentName,
            email: email,
            phone: phone,
            university: university,
            faculty: faculty,
            major: major,
            supervisor: supervisor,
            co_supervisor: coSupervisor,
            is_sponsored: isSponsored, // Supabase boolean handles true/false directly
            sponsor_company: sponsorCompany,
            company_mentor: companyMentor,
            grad_year: gradYear,
            domains: JSON.stringify(domains), // Store array as string
            project_title: projectTitle,
            peers_count: peersCount,
            doc_link: docLink
        }])
        .select();

    if (error) {
        console.error("Supabase Insert Error:", error.message);
        return res.status(500).json({ error: "Failed to save project: " + error.message });
    }

    res.json({ success: true, message: "Project registered successfully!", id: data[0].id });
});

// 3. API: Get All Projects (For Dashboard)
app.get('/api/grad-projects', async (req, res) => {
    // Select all columns, order by newest first
    const { data, error } = await supabase
        .from('graduation_projects')
        .select('*')
        .order('grad_year', { ascending: false })
        .order('submitted_at', { ascending: false });

    if (error) {
        console.error("Supabase Fetch Error:", error.message);
        return res.status(500).json({ error: "Database error" });
    }

    // Process data to match frontend expectations
    const processedRows = data.map(row => {
        let parsedDomains = [];
        try {
            // Parse JSON string back to Array, handle if it's already an object
            parsedDomains = typeof row.domains === 'string' ? JSON.parse(row.domains) : row.domains;
        } catch (e) {
            parsedDomains = [];
        }

        return {
            ...row,
            domains: parsedDomains || [],
            // Convert Boolean to "Yes/No" for the frontend display
            is_sponsored: row.is_sponsored ? 'Yes' : 'No' 
        };
    });

    res.json(processedRows);
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