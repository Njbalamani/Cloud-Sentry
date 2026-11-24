document.addEventListener("DOMContentLoaded", function () {
  const source = document.querySelector('meta[name="metrics-url"]');
  const severityCanvas = document.getElementById("severity-chart");
  const trendCanvas = document.getElementById("trend-chart");
  const resourceCanvas = document.getElementById("resource-type-chart");

  if (!source || !window.Chart || (!severityCanvas && !trendCanvas && !resourceCanvas)) {
    return;
  }

  Chart.defaults.color = "#93a4c4";
  Chart.defaults.font.family = "Inter, sans-serif";
  Chart.defaults.borderColor = "rgba(216, 180, 106, 0.12)";

  const palette = {
    critical: "#ff5f6d",
    high: "#ffb547",
    medium: "#d8b46a",
    low: "#64a8ff",
    info: "#9b7bff"
  };

  fetch(source.content, { headers: { "X-Requested-With": "XMLHttpRequest" } })
    .then(function (response) {
      if (!response.ok) {
        throw new Error("Metrics unavailable");
      }
      return response.json();
    })
    .then(function (metrics) {
      if (severityCanvas) {
        const severities = metrics.severity_counts || {};
        new Chart(severityCanvas, {
          type: "doughnut",
          data: {
            labels: Object.keys(severities).map(function (key) {
              return key.charAt(0).toUpperCase() + key.slice(1);
            }),
            datasets: [{
              data: Object.values(severities),
              backgroundColor: Object.keys(severities).map(function (key) {
                return palette[key] || "#d8b46a";
              }),
              borderWidth: 0,
              hoverOffset: 8
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
              legend: { position: "right", labels: { boxWidth: 10, boxHeight: 10 } }
            }
          }
        });
      }

      if (trendCanvas) {
        const trend = metrics.trend || [];
        const gradient = trendCanvas.getContext("2d").createLinearGradient(0, 0, 0, 240);
        gradient.addColorStop(0, "rgba(216, 180, 106, 0.38)");
        gradient.addColorStop(1, "rgba(216, 180, 106, 0.01)");
        new Chart(trendCanvas, {
          type: "line",
          data: {
            labels: trend.map(function (item) { return item.date.slice(5); }),
            datasets: [{
              label: "Findings",
              data: trend.map(function (item) { return item.total; }),
              borderColor: "#d8b46a",
              backgroundColor: gradient,
              borderWidth: 2,
              pointRadius: 3,
              tension: 0.38,
              fill: true
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { grid: { display: false } },
              y: { beginAtZero: true, ticks: { precision: 0 } }
            }
          }
        });
      }

      if (resourceCanvas) {
        const resources = metrics.resource_types || [];
        new Chart(resourceCanvas, {
          type: "bar",
          data: {
            labels: resources.map(function (item) { return item.type.replaceAll("_", " "); }),
            datasets: [{
              label: "Resources",
              data: resources.map(function (item) { return item.total; }),
              backgroundColor: "rgba(100, 168, 255, 0.45)",
              borderColor: "#64a8ff",
              borderWidth: 1,
              borderRadius: 6
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { grid: { display: false } },
              y: { beginAtZero: true, ticks: { precision: 0 } }
            }
          }
        });
      }
    })
    .catch(function () {
      [severityCanvas, trendCanvas, resourceCanvas].forEach(function (canvas) {
        if (canvas) {
          const parent = canvas.parentElement;
          if (parent) {
            parent.setAttribute("data-error", "Metrics could not be loaded.");
          }
        }
      });
    });
});
