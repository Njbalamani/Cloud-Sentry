document.addEventListener("DOMContentLoaded", function () {
  const source = document.querySelector('meta[name="topology-url"]');
  const stage = document.getElementById("topology-stage");
  const tooltip = document.getElementById("topology-tooltip");

  if (!source || !stage || !window.THREE) {
    return;
  }

  const riskColors = {
    account: 0xd8b46a,
    critical: 0xff5f6d,
    high: 0xffb547,
    medium: 0xd8b46a,
    low: 0x64a8ff,
    none: 0x45d9a6
  };

  fetch(source.content, { headers: { "X-Requested-With": "XMLHttpRequest" } })
    .then(function (response) {
      if (!response.ok) {
        throw new Error("Topology unavailable");
      }
      return response.json();
    })
    .then(function (topology) {
      const width = stage.clientWidth || 800;
      const height = stage.clientHeight || 380;
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
      camera.position.set(0, 2, 24);
      const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(width, height);
      stage.appendChild(renderer.domElement);

      scene.add(new THREE.AmbientLight(0x7ea7df, 1.2));
      const keyLight = new THREE.PointLight(0xd8b46a, 2.4, 80);
      keyLight.position.set(8, 10, 12);
      scene.add(keyLight);
      const fillLight = new THREE.PointLight(0x4d7bc4, 1.6, 80);
      fillLight.position.set(-10, -6, 8);
      scene.add(fillLight);

      const group = new THREE.Group();
      scene.add(group);
      const positions = new Map();
      const meshes = [];
      const nodes = topology.nodes || [];
      const links = topology.links || [];

      nodes.forEach(function (node, index) {
        const account = node.type === "cloud_account";
        const angle = index * 1.08;
        const radius = account ? 0 : 5 + (index % 4) * 1.6;
        const x = account ? 0 : Math.cos(angle) * radius;
        const y = account ? 0 : Math.sin(angle * 0.7) * 2.8;
        const z = account ? 0 : Math.sin(angle) * radius;
        positions.set(node.id, new THREE.Vector3(x, y, z));
        const geometry = account
          ? new THREE.IcosahedronGeometry(0.9, 1)
          : new THREE.SphereGeometry(0.28 + Math.min(node.finding_count || 0, 6) * 0.045, 20, 20);
        const color = riskColors[node.risk] || riskColors.none;
        const material = new THREE.MeshStandardMaterial({
          color: color,
          emissive: color,
          emissiveIntensity: account ? 0.45 : 0.22,
          transparent: true,
          opacity: 0.94,
          roughness: 0.35,
          metalness: 0.65
        });
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.copy(positions.get(node.id));
        mesh.userData = node;
        group.add(mesh);
        meshes.push(mesh);
        if (node.demo) {
          const halo = new THREE.Mesh(
            new THREE.RingGeometry(0.55, 0.62, 28),
            new THREE.MeshBasicMaterial({ color: 0x9b7bff, transparent: true, opacity: 0.5, side: THREE.DoubleSide })
          );
          halo.position.copy(mesh.position);
          halo.lookAt(camera.position);
          group.add(halo);
        }
      });

      links.forEach(function (link) {
        const from = positions.get(link.source);
        const to = positions.get(link.target);
        if (!from || !to) {
          return;
        }
        const geometry = new THREE.BufferGeometry().setFromPoints([from, to]);
        const material = new THREE.LineBasicMaterial({
          color: link.demo ? 0x9b7bff : 0xd8b46a,
          transparent: true,
          opacity: 0.38
        });
        group.add(new THREE.Line(geometry, material));
      });

      const raycaster = new THREE.Raycaster();
      const mouse = new THREE.Vector2();

      stage.addEventListener("mousemove", function (event) {
        const rect = stage.getBoundingClientRect();
        mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        const hits = raycaster.intersectObjects(meshes);
        if (!tooltip) {
          return;
        }
        if (hits.length) {
          const node = hits[0].object.userData;
          tooltip.innerHTML = "<strong>" + node.label + "</strong><br>" +
            "Type: " + node.type + "<br>Risk: " + node.risk + "<br>Findings: " + (node.finding_count || 0) +
            (node.demo ? "<br>Synthetic data" : "");
          tooltip.style.left = (event.clientX - rect.left + 14) + "px";
          tooltip.style.top = (event.clientY - rect.top + 14) + "px";
          tooltip.style.display = "block";
        } else {
          tooltip.style.display = "none";
        }
      });

      stage.addEventListener("mouseleave", function () {
        if (tooltip) {
          tooltip.style.display = "none";
        }
      });

      const resize = function () {
        const nextWidth = stage.clientWidth || 800;
        const nextHeight = stage.clientHeight || 380;
        camera.aspect = nextWidth / nextHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(nextWidth, nextHeight);
      };

      window.addEventListener("resize", resize);
      if (window.ResizeObserver) {
        new ResizeObserver(resize).observe(stage);
      }

      let frame = 0;
      const animate = function () {
        window.requestAnimationFrame(animate);
        frame += 0.012;
        group.rotation.y += 0.0014;
        group.rotation.x = Math.sin(frame * 0.15) * 0.08;
        meshes.forEach(function (mesh, index) {
          const scale = 1 + Math.sin(frame * 1.4 + index) * 0.035;
          mesh.scale.setScalar(scale);
        });
        renderer.render(scene, camera);
      };
      animate();

      window.addEventListener("beforeunload", function () {
        renderer.dispose();
      });
    })
    .catch(function () {
      if (stage) {
        stage.setAttribute("data-error", "Topology could not be loaded.");
      }
    });
});
