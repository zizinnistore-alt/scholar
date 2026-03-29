document.addEventListener("DOMContentLoaded", () => {
	// check if there are search parameters in the URL and auto-populate the search fields and trigger a search after the dom is loaded.
	if (globalThis.location.search) {
		const prams = new URLSearchParams(globalThis.location.search);
		document.getElementById("q").value = prams.get("query") || "";
		document.getElementById("desc").value = prams.get("description") || "";

		search()
			.then(() => {
				// After search completes, if there's an 'id' param, auto-analyze that target
				const autoId = prams.get("id");
				if (autoId) {
					analyzeTarget(autoId);
				}
			})
			.catch((e) => {
				console.error("Initial search error:", e);
			});
	}
});

/**
 * Pagination change event
 */
globalThis.addEventListener("paginationChanged", (e) => {
	search();
});
async function search() {
	const query = document.getElementById("q").value.trim();
	const desc = document.getElementById("desc").value.trim();
	if (!query && !desc)
		return alert(
			"Please enter a researcher name or mission parameters to scan.",
		);

	const prams = new URLSearchParams(globalThis.location.search);
	const pageNumber = prams.get("page") || 1;
	const pageSize = prams.get("limit") || 5;

	// Update URL with current search and pagination state
	SearchSyncManager.syncToURL({
		query,
		page: pageNumber,
		limit: pageSize,
		description: desc,
	});

	document.getElementById("pagination").innerHTML = "";
	// Clear pagination on new search

	const list = document.getElementById("results-list");

	list.innerHTML = `
                <div style="text-align:center; padding: 20px; color: var(--accent);">
                    <i class="fas fa-circle-notch fa-spin" style="font-size: 2rem; margin-bottom: 10px;"></i>
                    <div style="font-weight: 600; font-size: 0.9rem;">SCANNING DATABASE...</div>
                </div>
            `;

	try {
		const res = await axios
			.get(`/api/search`, {
				params: {
					query,
					description: desc,
					page: pageNumber,
					limit: pageSize,
				},
			})
			.catch((e) => {
				console.error("API error:", e);
				throw new Error("Failed to fetch search results.");
			});
		console.log(res.data);
		const data = res.data.authors || [];
		list.innerHTML = "";

		if (data.length === 0) {
			list.innerHTML =
				'<div style="text-align:center; color:var(--text-muted); padding:20px;">No targets found.</div>';
			return;
		}

		data.forEach((a) => {
			const div = document.createElement("div");
			div.className = "author-card-mini";
			div.innerHTML = `
                        <div class="ac-name">${a.name}</div>
                        <div class="field-badge">${a.primaryField || "Researcher"}</div>
                        <div class="ac-stats">
                            <span><i class="fas fa-chart-line" style="color:var(--success)"></i> H-Idx: ${a.hIndex}</span>
                            <span><i class="fas fa-file-alt" style="color:var(--accent)"></i> Papers: ${a.paperCount}</span>
                        </div>
                    `;
			div.onclick = () => analyzeTarget(a.authorId);
			list.appendChild(div);
		});

		new Pagination(
			"pagination",
			Math.ceil(res.data.total / pageSize),
			pageSize,
		).render();
	} catch (e) {
		console.error("Search error:", e);
		list.innerHTML =
			'<div style="color:var(--danger); text-align:center; padding:20px;">Error contacting server.</div>';
	}
}

async function analyzeTarget(id) {
	const view = document.getElementById("main-view");
	const desc = document.getElementById("desc").value;

	view.innerHTML = `
                <div style="text-align:center; margin-top:100px;">
                    <i class="fas fa-circle-notch fa-spin" style="font-size:3.5rem; color:var(--accent); margin-bottom:25px;"></i>
                    <h2 style="font-family:var(--font-header); color:var(--text-main); margin:0 0 10px 0;">ANALYZING PROFILE...</h2>
                    <p style="color:var(--text-muted);">Processing publications, citations, and AI matching score.</p>
                </div>
            `;

	SearchSyncManager.syncToURL({
		query,
		page: pageNumber,
		limit: pageSize,
		description: desc,
	});

	try {
		const res = await fetch("/api/analyze", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ authorId: id, userDescription: desc }),
		});
		const data = await res.json();
		const { author, analysis, collaborators } = data;

		let scoreColor = "var(--danger)";
		if (analysis.match_score >= 50) scoreColor = "var(--warning)";
		if (analysis.match_score >= 80) scoreColor = "var(--success)";

		view.innerHTML = `
                    <!-- (Header) -->
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:25px; padding-bottom:20px; border-bottom:1px solid var(--border);">
                        <div>
                            <h1 style="margin:0; font-family:var(--font-header); font-size:2.2rem; color:var(--text-main);">${author.name}</h1>
                            <div style="color:var(--text-muted); font-size:1rem; margin-top:8px; font-weight:500;">
                                <i class="fas fa-layer-group" style="color:var(--accent); margin-right:5px;"></i> Primary Field: <span style="color:var(--text-main)">${author.primaryField}</span>
                            </div>
                        </div>
                        <a href="${author.url}" target="_blank" class="btn-action" style="width:auto; padding:10px 20px; font-size:0.9rem; text-decoration:none;">
                            View Profile <i class="fas fa-external-link-alt"></i>
                        </a>
                    </div>

                    <div class="match-container" style="border-left: 4px solid ${scoreColor};">
                        <div style="flex: 1; padding-right: 20px;">
                            <div style="font-family:var(--font-header); font-size:1.2rem; font-weight:700; color:var(--text-main); margin-bottom:8px;">
                                RELEVANCE MATCH
                            </div>
                            <div style="color:var(--text-muted); font-size:0.95rem; line-height:1.6;">
                                ${analysis.match_reason}
                            </div>
                        </div>
                        <div class="gauge-wrapper">
                            <svg width="90" height="90">
                                <circle cx="45" cy="45" r="38" stroke="var(--border)" stroke-width="8" fill="none"></circle>
                                <circle cx="45" cy="45" r="38" stroke="${scoreColor}" stroke-width="8" fill="none" stroke-dasharray="239" stroke-dashoffset="${239 - (239 * analysis.match_score) / 100}" class="gauge-circle" style="transition: stroke-dashoffset 1.5s ease-out; stroke-linecap: round;"></circle>
                            </svg>
                            <div class="gauge-text">${analysis.match_score}%</div>
                        </div>
                    </div>

                    <!--(Stats) -->
                    <div class="dash-grid">
                        <div class="stat-box">
                            <div class="sb-val">${author.hIndex}</div>
                            <div class="sb-lbl" style="color:var(--success)">H-Index</div>
                        </div>
                        <div class="stat-box">
                            <div class="sb-val">${new Intl.NumberFormat().format(author.citationCount)}</div>
                            <div class="sb-lbl" style="color:var(--accent)">Total Citations</div>
                        </div>
                        <div class="stat-box">
                            <div class="sb-val">${author.paperCount}</div>
                            <div class="sb-lbl" style="color:#a855f7">Publications</div>
                        </div>
                    </div>

                    <div class="ai-report">
                        <div class="ai-header"><i class="fas fa-robot" style="color:var(--accent)"></i> AI Expert Analysis</div>
                        <div style="margin-bottom:20px;">
                            ${analysis.key_technologies.map((t) => `<span class="tech-tag">${t}</span>`).join("")}
                        </div>
                        <div id="report-text" style="color:var(--text-main)">
                            ${analysis.full_report.replace(/\n/g, "<br><br>")}
                        </div>
                    </div>

                    <div style="display:grid; grid-template-columns: 2fr 1fr; gap:30px;">
                        
                        <!-- Top Papers -->
                        <div>
                            <div class="section-title"><i class="fas fa-book-open" style="color:var(--accent)"></i> Top Transmissions</div>
                            ${author.papers
															.slice(0, 10)
															.map(
																(p) => `
                                <div class="paper-row">
                                    <span class="p-year">${p.year || "N/A"}</span>
                                    <div>
                                        <a href="${p.url}" target="_blank" class="p-title">${p.title}</a>
                                        <div class="p-meta">
                                            <i class="fas fa-quote-right" style="color:var(--success)"></i> ${p.citationCount} citations 
                                            &nbsp;&bull;&nbsp; ${p.venue || "Journal"} 
                                            &nbsp;&bull;&nbsp; ${p.fieldsOfStudy || "General Science"}
                                        </div>
                                    </div>
                                </div>
                            `,
															)
															.join("")}
                        </div>

                        <!-- Network -->
                        <div>
                            <div class="section-title"><i class="fas fa-project-diagram" style="color:#a855f7"></i> Core Network</div>
                            <div style="background:var(--bg-card); padding:20px; border-radius:12px; border:1px solid var(--border);">
                                ${
																	collaborators.length > 0
																		? collaborators
																				.map(
																					(c) => `
                                        <div class="network-row">
                                            <span style="color:var(--text-main); font-weight:500;">${c}</span>
                                            <span style="color:var(--accent); font-weight:700; background:rgba(59,130,246,0.1); padding:2px 8px; border-radius:12px; font-size:0.8rem;">${c}x</span>
                                        </div>
                                    `,
																				)
																				.join("")
																		: '<div style="color:var(--text-muted); text-align:center; padding:10px;">No collaboration data available.</div>'
																}
                            </div>
                        </div>

                    </div>
                `;
	} catch (e) {
		console.error("Analysis error:", e);
		view.innerHTML = `
                    <div style="background: rgba(239, 68, 68, 0.1); padding: 40px; text-align: center; border-radius: 12px; border: 1px solid rgba(239, 68, 68, 0.2);">
                        <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: var(--danger); margin-bottom: 15px;"></i>
                        <h3 style="margin: 0; color: var(--danger);">Analysis Failed</h3>
                        <p style="color: var(--text-muted); margin-top: 10px;">Unable to fetch data for this researcher.</p>
                    </div>
                `;
	}
}

// --- Auto-Search Logic on Redirect  ---
window.onload = function () {
	const urlParams = new URLSearchParams(globalThis.location.search);
	const autoId = urlParams.get("id");
	const autoName = urlParams.get("n");
	const autoQuery = urlParams.get("q");

	if (autoName) {
		document.getElementById("q").value = autoName;
	} else if (autoQuery) {
		document.getElementById("q").value = autoQuery;
	}

	if (autoId) {
		analyzeTarget(autoId);
	} else if (autoQuery) {
		search();
	}
};
