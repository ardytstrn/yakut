// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="index.html"><strong aria-hidden="true">1.</strong> Introduction</a></li><li class="chapter-item expanded "><a href="faq-troubleshooting.html"><strong aria-hidden="true">2.</strong> FAQ &amp; Troubleshooting</a></li><li class="chapter-item expanded "><a href="getting-started/index.html"><strong aria-hidden="true">3.</strong> Getting Started</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="getting-started/prerequisites.html"><strong aria-hidden="true">3.1.</strong> Prerequisites</a></li><li class="chapter-item expanded "><a href="getting-started/installation.html"><strong aria-hidden="true">3.2.</strong> Installation</a></li><li class="chapter-item expanded "><a href="getting-started/initial-configuration.html"><strong aria-hidden="true">3.3.</strong> Initial Configuration</a></li><li class="chapter-item expanded "><a href="getting-started/first-run.html"><strong aria-hidden="true">3.4.</strong> First Run</a></li></ol></li><li class="chapter-item expanded "><a href="user-guide/index.html"><strong aria-hidden="true">4.</strong> User Guide</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="user-guide/cli-overview.html"><strong aria-hidden="true">4.1.</strong> CLI Overview</a></li><li class="chapter-item expanded "><a href="user-guide/core-concepts.html"><strong aria-hidden="true">4.2.</strong> Core Concepts</a></li><li class="chapter-item expanded "><a href="user-guide/common-commands.html"><strong aria-hidden="true">4.3.</strong> Common Commands</a></li><li class="chapter-item expanded "><a href="user-guide/working-with-capabilities.html"><strong aria-hidden="true">4.4.</strong> Working with Capabilities</a></li><li class="chapter-item expanded "><a href="user-guide/payload-management.html"><strong aria-hidden="true">4.5.</strong> Payload Management</a></li><li class="chapter-item expanded "><a href="user-guide/session-handling.html"><strong aria-hidden="true">4.6.</strong> Session Handling</a></li><li class="chapter-item expanded "><a href="user-guide/data-management-reporting.html"><strong aria-hidden="true">4.7.</strong> Data Management &amp; Reporting</a></li><li class="chapter-item expanded "><a href="user-guide/scripting-automation.html"><strong aria-hidden="true">4.8.</strong> Scripting &amp; Automation</a></li></ol></li><li class="chapter-item expanded "><a href="developer-guide/index.html"><strong aria-hidden="true">5.</strong> Developer Guide</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer-guide/architectural-overview.html"><strong aria-hidden="true">5.1.</strong> Architectural Overview</a></li><li class="chapter-item expanded "><a href="developer-guide/capability-development/index.html"><strong aria-hidden="true">5.2.</strong> Capability Development</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer-guide/capability-anatomy-structure.html"><strong aria-hidden="true">5.2.1.</strong> Capability Anatomy &amp; Structure</a></li></ol></li></ol></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
