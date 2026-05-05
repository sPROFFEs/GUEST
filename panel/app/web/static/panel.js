// Tiny vanilla helpers used across the panel. Loaded from base.html.
(function () {
    "use strict";

    /* ----------- Confirm modal ----------- */
    // Replaces native confirm(). Use as:
    //   <form onsubmit="return panelConfirm(this, 'Delete this rule?')">
    window.panelConfirm = function (form, message) {
        const dlg = document.getElementById("confirm-modal");
        if (!dlg) return window.confirm(message);  // graceful fallback
        document.getElementById("confirm-modal-msg").textContent = message;
        const ok = document.getElementById("confirm-modal-ok");
        const cancel = document.getElementById("confirm-modal-cancel");
        const close = () => dlg.close();
        ok.onclick = () => { close(); form.submit(); };
        cancel.onclick = close;
        dlg.showModal();
        return false;  // suppress the original submit
    };

    /* ----------- Sortable tables ----------- */
    // <th class="sortable" onclick="sortTable(this)">…</th>
    // Auto-detects numeric vs text columns; toggles asc/desc on repeated clicks.
    window.sortTable = function (th) {
        const table = th.closest("table");
        if (!table || !table.tBodies[0]) return;
        const tbody = table.tBodies[0];
        const headers = Array.from(th.parentNode.children);
        const idx = headers.indexOf(th);
        const asc = !th.classList.contains("sort-asc");
        const rows = Array.from(tbody.rows);

        const num = (v) => {
            const n = parseFloat(String(v).replace(/[^\d.\-]/g, ""));
            return isNaN(n) ? null : n;
        };
        rows.sort((a, b) => {
            const av = (a.cells[idx]?.innerText || "").trim();
            const bv = (b.cells[idx]?.innerText || "").trim();
            const an = num(av), bn = num(bv);
            if (an !== null && bn !== null) return asc ? an - bn : bn - an;
            return asc ? av.localeCompare(bv, undefined, {numeric:true}) :
                         bv.localeCompare(av, undefined, {numeric:true});
        });
        rows.forEach(r => tbody.appendChild(r));
        headers.forEach(h => h.classList.remove("sort-asc","sort-desc"));
        th.classList.add(asc ? "sort-asc" : "sort-desc");
    };

    /* ----------- Inline validation ----------- */
    // Bare-IP or CIDR. Empty input is allowed (the form's `required` attribute
    // handles emptiness). Sets customValidity so the browser shows the message.
    window.validateCIDR = function (input) {
        const v = (input.value || "").trim();
        if (!v) { input.setCustomValidity(""); return; }
        const re = /^(\d{1,3}\.){3}\d{1,3}(\/(3[0-2]|[12]?\d))?$/;
        const parts = v.split("/")[0].split(".");
        const okOctets = parts.length === 4 && parts.every(p => +p >= 0 && +p <= 255);
        if (!re.test(v) || !okOctets) {
            input.setCustomValidity("Use a single IP (192.168.100.211) or a CIDR (192.168.100.0/24).");
        } else {
            input.setCustomValidity("");
        }
    };

    window.validatePort = function (input) {
        const v = (input.value || "").trim();
        if (!v) { input.setCustomValidity(""); return; }
        const n = parseInt(v, 10);
        if (!/^\d+$/.test(v) || n < 1 || n > 65535) {
            input.setCustomValidity("Port must be 1–65535.");
        } else {
            input.setCustomValidity("");
        }
    };

    /* ----------- Sparkline (inline SVG) ----------- */
    // Renders a polyline into <svg data-sparkline data-points="1,2,3,4">.
    // Run on DOMContentLoaded.
    function drawSparkline(svg) {
        const raw = (svg.getAttribute("data-points") || "").trim();
        if (!raw) return;
        const pts = raw.split(",").map(parseFloat).filter(n => !isNaN(n));
        if (pts.length < 2) return;
        const w = svg.viewBox.baseVal.width  || 200;
        const h = svg.viewBox.baseVal.height || 40;
        const max = Math.max(...pts, 1);
        const min = Math.min(...pts, 0);
        const range = (max - min) || 1;
        const stepX = w / (pts.length - 1);
        const coords = pts.map((v, i) => `${(i*stepX).toFixed(2)},${(h - ((v - min)/range)*h).toFixed(2)}`).join(" ");
        const ns = "http://www.w3.org/2000/svg";
        const poly = document.createElementNS(ns, "polyline");
        poly.setAttribute("points", coords);
        poly.setAttribute("fill", "none");
        poly.setAttribute("stroke", svg.getAttribute("data-color") || "#5b9cff");
        poly.setAttribute("stroke-width", "1.5");
        svg.appendChild(poly);
        // Filled area under the line, very subtle.
        const area = document.createElementNS(ns, "polyline");
        area.setAttribute("points", `0,${h} ${coords} ${w},${h}`);
        area.setAttribute("fill", svg.getAttribute("data-color") || "#5b9cff");
        area.setAttribute("opacity", "0.12");
        area.setAttribute("stroke", "none");
        svg.insertBefore(area, poly);
    }

    document.addEventListener("DOMContentLoaded", () => {
        document.querySelectorAll("svg[data-sparkline]").forEach(drawSparkline);
    });
})();
