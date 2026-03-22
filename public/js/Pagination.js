/**
 * Pagination class that syncs with URL search params
 * Works with SearchSyncManager for URL state management
 */
class Pagination {
	constructor(containerId, totalPages, limit = 10) {
		this.container = document.getElementById(containerId);
		this.totalPages = totalPages;
		this.limit = limit;
	}

	/**
	 * Get current page from URL params
	 * @returns {number} Current page number (1-indexed)
	 */
	getCurrentPage() {
		const params = new URLSearchParams(globalThis.location.search);
		return +params.get("page") || 1;
	}

	/**
	 * Update URL with new page (preserves all other params)
	 * @param {number} page - Page number to navigate to
	 */
	updatePage(page) {
		// Get all current params from URL
		const currentParams = new URLSearchParams(globalThis.location.search);

		// Update page param
		currentParams.set("page", page);
		currentParams.set("limit", this.limit);

		// Use replaceState here - pagination nav doesn't warrant back button history
		globalThis.history.replaceState(
			{ page },
			"",
			`${globalThis.location.pathname}?${currentParams}`,
		);

		// Trigger a custom event so page can listen and re-fetch
		globalThis.dispatchEvent(
			new CustomEvent("paginationChanged", { detail: { page } }),
		);
	}

	/**
	 * Create a pagination button
	 * @param {string} label - Button text/label
	 * @param {number} page - Page number for this button
	 * @param {Object} options - { active: bool, disabled: bool }
	 * @returns {HTMLElement} Button element
	 */
	createButton(label, page, options = {}) {
		const btn = document.createElement("button");
		btn.textContent = label;
		btn.type = "button";

		if (options.active) {
			btn.classList.add("active");
			btn.setAttribute("aria-current", "page");
		}

		if (options.disabled) {
			btn.disabled = true;
			btn.setAttribute("aria-disabled", "true");
		} else {
			btn.addEventListener("click", () => this.updatePage(page));
		}

		return btn;
	}

	/**
	 * Render pagination UI
	 * Shows previous, nearby pages, ellipsis, and next
	 */
	render() {
		const current = this.getCurrentPage();
		const wrapper = document.createElement("div");
		wrapper.className = "pagination";
		wrapper.setAttribute("role", "navigation");
		wrapper.setAttribute("aria-label", "Pagination navigation");

		// Previous button
		wrapper.appendChild(
			this.createButton("←", current - 1, { disabled: current === 1 }),
		);

		// Determine which pages to show
		let pages = [];
		if (current === 1) {
			pages = [1, 2, 3];
		} else if (current === this.totalPages) {
			pages = [this.totalPages - 2, this.totalPages - 1, this.totalPages];
		} else {
			pages = [current - 1, current, current + 1];
		}

		// Add page buttons
		pages.forEach((p) => {
			if (p >= 1 && p <= this.totalPages) {
				wrapper.appendChild(
					this.createButton(`${p}`, p, { active: p === current }),
				);
			}
		});

		// Add ellipsis if there's a gap
		if (pages.at(-1) < this.totalPages - 1) {
			const ellipsis = document.createElement("span");
			ellipsis.textContent = "...";
			ellipsis.className = "ellipsis";
			ellipsis.setAttribute("aria-hidden", "true");
			wrapper.appendChild(ellipsis);
		}

		// Add last page button if not already shown
		// if (pages.at(-1) < this.totalPages) {
		// 	wrapper.appendChild(
		// 		this.createButton(`${this.totalPages}`, this.totalPages),
		// 	);
		// }

		// Next button
		wrapper.appendChild(
			this.createButton("→", current + 1, {
				disabled: current === this.totalPages,
			}),
		);

		// Clear and re-render
		this.container.innerHTML = "";
		this.container.appendChild(wrapper);
	}
}
