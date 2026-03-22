document.addEventListener("DOMContentLoaded", () => {
	if (globalThis.location.search) {
		const params = new URLSearchParams(globalThis.location.search);
		const query = params.get("query");
		const paperId = params.get("paperId");
		const year = params.get("year");
		const mode = paperId ? "recommend" : "search";
		document.getElementById("q-input").value = query || "";
		document.getElementById("q-id").value = paperId || "";
		document.getElementById("f-year").value = year || "";
		fetchPapers(mode, paperId).then(() => {
			// Scroll to results after loading
			document
				.getElementById("main-view")
				.scrollIntoView({ behavior: "smooth" });
		});
	}
});

/**
 * Pagination change event
 */
globalThis.addEventListener("paginationChanged", (e) => {
	fetchPapers("search");
});

/**
 * Back button support: re-perform search when URL changes
 */
globalThis.addEventListener("popstate", () => {
	// populateFormFromURL();
	fetchPapers("search");
});

async function fetchPapers(mode, specificId = null) {
	const year = document.getElementById("f-year").value.trim();
	const query = document.getElementById("q-input").value.trim();
	const paperIdInput = document.getElementById("q-id").value.trim();

	const view = document.getElementById("searchResult");
	let { limit, page } = getPaginationParams();

	// Determine effective ID and Mode
	let effectiveId = specificId || paperIdInput;
	let effectiveMode = mode;

	// If user clicked Search but filled in ID, switch to recommendation mode
	if (mode === "search" && effectiveId && !query) {
		effectiveMode = "recommend";
	}

	if (effectiveMode === "search" && !query) {
		alert("Please enter a search query.");
		return;
	}

	if (query !== new URLSearchParams(globalThis.location.search).get("query")) {
		// If the query has changed from the URL, reset to page 1
		page = 1;
	}

	document.getElementById("pagination").innerHTML = "";

	// Loading State
	view.innerHTML = `
                <div class="loading-state">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    <h3>Retrieving Papers...</h3>
                    <p>Fetching data from Semantic Scholar API</p>
                </div>
            `;

	// Update URL with current search and pagination state
	SearchSyncManager.syncToURL({
		page,
		limit,
		query,
		year,
		paperId: effectiveId,
	});

	try {
		const res = await axios.get("/api/explore", {
			params: {
				mode: effectiveMode,
				query,
				paperId: effectiveId,
				year,
				limit,
				offset: page * limit - limit,
			},
		});

		const data = res.data;
		console.log(data);

		if (!data.papers || data.papers.length === 0) {
			view.innerHTML = `<div style="text-align:center; padding: 3rem;"><h3>No papers found.</h3></div>`;
			return;
		}

		// Render Header
		let html = `
                    <div class="results-header">
                        <span>Found <strong>${data.total || data.papers.length}</strong> Results for "${effectiveMode === "recommend" ? "Similar to " + effectiveId : query}"</span>
                    </div>
                `;

		// Render Cards
		data.papers.forEach((p) => {
			const authors = p.authors
				? p.authors.map((a) => a.name).join(", ")
				: "Unknown Authors";
			const venue = p.venue || "Unknown Venue";
			const abstract = p.abstract || "No abstract available for this paper.";
			const citations = p.citationCount || 0;
			const pdfLink = p.openAccessPdf ? p.openAccessPdf.url : null;
			const s2Link = p.url;

			html += `
                    <div class="paper-card">
                        <div class="paper-title">
                            <a href="${s2Link}" target="_blank">${p.title}</a>
                            ${pdfLink ? '<span class="badge-oa"><i class="fas fa-lock-open"></i> OA</span>' : ""}
                        </div>
                        
                        <div class="paper-authors">${authors}</div>
                        
                        <div class="paper-meta">
                            <div class="meta-item"><i class="far fa-calendar"></i> ${p.year || "N/A"}</div>
                            <div class="meta-item"><i class="fas fa-university"></i> ${venue}</div>
                            <div class="meta-item"><i class="fas fa-quote-right"></i> ${citations} Citations</div>
                        </div>

                        <div class="paper-abstract">${abstract}</div>

                        <div class="paper-actions">
                            ${pdfLink ? `<a href="${pdfLink}" target="_blank" class="btn-sm"><i class="fas fa-file-pdf"></i> PDF</a>` : ""}
                            <a href="${s2Link}" target="_blank" class="btn-sm"><i class="fas fa-external-link-alt"></i> View on S2</a>
                            <button onclick="fetchPapers('recommend', '${p.paperId}')" class="btn-sm primary">
                                <i class="fas fa-project-diagram"></i> Find Similar
                            </button>
                        </div>
                    </div>
                    `;
		});

		view.innerHTML = html;

		new Pagination("pagination", Math.ceil(data.total / limit), limit).render();
	} catch (e) {
		console.error(e);
		view.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-search"></i>
                        <h3>No papers found</h3>
                        <p>Try adjusting your search filters...</p>
                    </div>
                `;
	}
}
function getPaginationParams() {
	const params = new URLSearchParams(globalThis.location.search);
	return {
		page: +params.get("page") || 1,
		limit: +params.get("limit") || 10,
	};
}
