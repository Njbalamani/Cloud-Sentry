document.addEventListener("DOMContentLoaded", function () {
  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("loading-overlay");

  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      sidebar.classList.toggle("open");
    });
  }

  document.querySelectorAll(".nav-link").forEach(function (link) {
    link.addEventListener("click", function () {
      if (window.innerWidth <= 900 && sidebar) {
        sidebar.classList.remove("open");
      }
    });
  });

  document.querySelectorAll("form").forEach(function (form) {
    if (form.dataset.noLoader === "true") {
      return;
    }
    form.addEventListener("submit", function (event) {
      const submitter = event.submitter;
      if (submitter && submitter.dataset.noLoader === "true") {
        return;
      }
      if (!form.checkValidity()) {
        return;
      }
      if (overlay) {
        overlay.classList.add("visible");
      }
    });
  });

  window.addEventListener("pageshow", function (event) {
    if (event.persisted && overlay) {
      overlay.classList.remove("visible");
    }
  });

  window.setTimeout(function () {
    if (overlay) {
      overlay.classList.remove("visible");
    }
  }, 1200);

  document.querySelectorAll(".message").forEach(function (message) {
    window.setTimeout(function () {
      message.style.transition = "opacity 0.3s ease, transform 0.3s ease";
      message.style.opacity = "0";
      message.style.transform = "translateY(-6px)";
      window.setTimeout(function () {
        message.remove();
      }, 320);
    }, 6500);
  });

  document.querySelectorAll("input[type='password']").forEach(function (input) {
    input.setAttribute("autocomplete", "current-password");
  });
});
