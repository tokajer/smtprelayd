// Selection helpers for the queue page's bulk requeue/delete form. Served
// from the dashboard's own origin, so script-src 'self' covers it; no inline
// script and no eval, which is what keeps the CSP as narrow as it is.
//
// Everything is delegated from the document rather than bound to the table,
// because htmx replaces the whole #queue-live region on every refresh and
// per-element handlers would be lost with it.
(function () {
	"use strict";

	function bulkForm() {
		return document.querySelector("[data-queue-bulk]");
	}

	function pickers(form) {
		return form.querySelectorAll('input[type="checkbox"][name="id"]');
	}

	function selected(form) {
		var boxes = pickers(form);
		var n = 0;
		for (var i = 0; i < boxes.length; i++) {
			if (boxes[i].checked) {
				n++;
			}
		}
		return n;
	}

	// refresh keeps the counter and the select-all box in step with the
	// actual selection. The counter names the paused auto-refresh too: a
	// table that visibly stops updating while boxes are ticked would
	// otherwise look like a broken page.
	function refresh() {
		var form = bulkForm();
		if (!form) {
			return;
		}
		var total = pickers(form).length;
		var n = selected(form);

		var label = form.querySelector("[data-selected-count]");
		if (label) {
			label.textContent = n === 0 ? "none selected" : n + " selected, auto-refresh paused";
		}
		var master = form.querySelector("[data-select-all]");
		if (master) {
			master.checked = n > 0 && n === total;
			master.indeterminate = n > 0 && n < total;
		}
	}

	document.addEventListener("change", function (event) {
		var target = event.target;
		if (!target || target.type !== "checkbox" || !target.closest) {
			return;
		}
		var form = target.closest("[data-queue-bulk]");
		if (!form) {
			return;
		}
		if (target.hasAttribute("data-select-all")) {
			var boxes = pickers(form);
			for (var i = 0; i < boxes.length; i++) {
				boxes[i].checked = target.checked;
			}
		}
		refresh();
	});

	// The queue table re-fetches itself every ten seconds. Let that swap
	// happen only while nothing is selected: replacing the table would throw
	// away a selection the operator is still building, which is the same
	// objection that keeps the search page's results table out of the
	// polling set entirely.
	document.addEventListener("htmx:beforeRequest", function (event) {
		var elt = event.detail && event.detail.elt;
		if (!elt || elt.id !== "queue-live") {
			return;
		}
		var form = bulkForm();
		if (form && selected(form) > 0) {
			event.preventDefault();
		}
	});

	document.addEventListener("htmx:afterSwap", refresh);
	document.addEventListener("DOMContentLoaded", refresh);
})();
