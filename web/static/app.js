"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const KEY_STORAGE = "pysri.apiKey";
  let lastXml = null;
  let lastName = "comprobante.xml";

  // ---------------------------------------------------------------- api key
  try { $("apiKey").value = sessionStorage.getItem(KEY_STORAGE) || ""; } catch (_) { /* sin storage */ }
  $("apiKey").addEventListener("change", () => {
    try { sessionStorage.setItem(KEY_STORAGE, $("apiKey").value.trim()); } catch (_) { /* sin storage */ }
    loadConfig();
  });

  function headers(extra) {
    const h = Object.assign({}, extra || {});
    const key = $("apiKey").value.trim();
    if (key) h["X-API-Key"] = key;
    return h;
  }

  async function api(method, url, body, isJson) {
    const opts = { method, headers: headers(isJson ? { "Content-Type": "application/json" } : {}), credentials: "omit" };
    if (body !== undefined) opts.body = body;
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      const err = new Error((data && data.detail) || `Error HTTP ${res.status}`);
      err.details = data && data.errores;
      throw err;
    }
    return data;
  }

  async function loadConfig() {
    try {
      const cfg = await api("GET", "/api/v1/config");
      $("serverInfo").textContent = cfg.allowProduction
        ? "Servidor habilitado para PRUEBAS y PRODUCCIÓN."
        : "Servidor habilitado solo para el ambiente de PRUEBAS.";
    } catch (e) {
      $("serverInfo").textContent = e.message;
    }
  }

  // ---------------------------------------------------------------- ui
  function show(statusText, kind, messages, output) {
    $("resultCard").hidden = false;
    const st = $("status");
    st.textContent = statusText;
    st.className = "status " + (kind || "");
    const ul = $("messages");
    ul.replaceChildren();
    (messages || []).forEach((m) => {
      const li = document.createElement("li");
      li.textContent = m;
      ul.appendChild(li);
    });
    $("output").textContent = output || "";
    $("btnDownload").hidden = !lastXml;
    $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function showError(e) {
    lastXml = null;
    const msgs = (e.details || []).map((d) => (d.campo ? `${d.campo}: ${d.error}` : d.error));
    show(e.message, "error", msgs, "");
  }

  function sriMessages(list) {
    return (list || []).map((m) =>
      [m.identificador, m.mensaje, m.informacionAdicional].filter(Boolean).join(" · "));
  }

  function setBusy(busy) {
    document.querySelectorAll("button").forEach((b) => { b.disabled = busy; });
  }

  async function run(fn) {
    setBusy(true);
    try { await fn(); } catch (e) { showError(e); } finally { setBusy(false); }
  }

  function invoiceText() {
    const raw = $("invoice").value.trim();
    try { JSON.parse(raw); } catch (_) { throw new Error("La factura no es un JSON válido"); }
    return raw;
  }

  function certForm() {
    const file = $("cert").files[0];
    if (!file) throw new Error("Seleccione el certificado .p12");
    if (file.size > 100 * 1024) throw new Error("El certificado es demasiado grande");
    const pwd = $("password").value;
    if (!pwd) throw new Error("Ingrese la contraseña del certificado");
    const fd = new FormData();
    fd.append("certificate", file, file.name);
    fd.append("password", pwd);
    fd.append("invoice", invoiceText());
    return fd;
  }

  // ---------------------------------------------------------------- acciones
  $("btnFormat").addEventListener("click", () => {
    try { $("invoice").value = JSON.stringify(JSON.parse($("invoice").value), null, 2); }
    catch (_) { showError(new Error("La factura no es un JSON válido")); }
  });

  $("btnExample").addEventListener("click", () => { $("invoice").value = JSON.stringify(example(), null, 2); });

  $("btnValidate").addEventListener("click", () => run(async () => {
    const data = await api("POST", "/api/v1/invoices/validate", invoiceText(), true);
    lastXml = data.xml; lastName = `${data.accessKey}.xml`;
    $("accessKey").value = data.accessKey;
    show(`Factura válida. Clave de acceso: ${data.accessKey}`, "ok", [], data.xml);
  }));

  $("btnSign").addEventListener("click", () => run(async () => {
    const data = await api("POST", "/api/v1/invoices/sign", certForm());
    lastXml = data.signedXml; lastName = `${data.accessKey}-firmado.xml`;
    $("accessKey").value = data.accessKey;
    show(`Factura firmada. Clave de acceso: ${data.accessKey}`, "ok",
      [`Certificado: ${data.certificateSubject}`, `Vence: ${data.certificateExpires}`], data.signedXml);
  }));

  $("btnSend").addEventListener("click", () => run(async () => {
    const data = await api("POST", "/api/v1/invoices/send", certForm());
    $("accessKey").value = data.accessKey;
    const a = data.authorization;
    lastXml = (a && a.comprobante) || data.signedXml;
    lastName = `${data.accessKey}${data.authorized ? "-autorizado" : "-firmado"}.xml`;
    const msgs = [`Recepción: ${data.reception.estado}`, ...sriMessages(data.reception.mensajes)];
    if (a) {
      msgs.push(`Autorización: ${a.estado}`);
      if (a.numeroAutorizacion) msgs.push(`N.º autorización: ${a.numeroAutorizacion}`);
      if (a.fechaAutorizacion) msgs.push(`Fecha: ${a.fechaAutorizacion}`);
      msgs.push(...sriMessages(a.mensajes));
    }
    show(data.authorized ? "Comprobante AUTORIZADO" : "Comprobante no autorizado", data.authorized ? "ok" : "warn",
      msgs, lastXml);
  }));

  $("btnAuth").addEventListener("click", () => run(async () => {
    const key = $("accessKey").value.trim();
    if (!/^\d{49}$/.test(key)) throw new Error("La clave de acceso debe tener 49 dígitos");
    const a = await api("GET", `/api/v1/invoices/${encodeURIComponent(key)}/authorization`);
    lastXml = a.comprobante || null; lastName = `${key}-autorizado.xml`;
    const msgs = [];
    if (a.numeroAutorizacion) msgs.push(`N.º autorización: ${a.numeroAutorizacion}`);
    if (a.fechaAutorizacion) msgs.push(`Fecha: ${a.fechaAutorizacion}`);
    show(`Estado: ${a.estado}`, a.estado === "AUTORIZADO" ? "ok" : "warn", msgs.concat(sriMessages(a.mensajes)),
      a.comprobante || "");
  }));

  $("btnDownload").addEventListener("click", () => {
    if (!lastXml) return;
    const blob = new Blob([lastXml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = lastName.replace(/[^\w.-]/g, "_");
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  // ---------------------------------------------------------------- ejemplo
  function example() {
    const now = new Date(Date.now() - 5 * 3600 * 1000); // hora de Ecuador (UTC-5)
    const d = now.toISOString().slice(0, 10);
    return {
      infoTributaria: {
        ambiente: "1",
        razonSocial: "EMPRESA DE PRUEBA S.A.",
        nombreComercial: "MI TIENDA",
        ruc: "1712345675001",
        estab: "001",
        ptoEmi: "001",
        secuencial: "1",
        dirMatriz: "Av. Amazonas N1-23, Quito",
      },
      infoFactura: {
        fechaEmision: d,
        dirEstablecimiento: "Av. Amazonas N1-23, Quito",
        obligadoContabilidad: "NO",
        tipoIdentificacionComprador: "05",
        razonSocialComprador: "JUAN PEREZ",
        identificacionComprador: "0923456784",
        direccionComprador: "Guayaquil",
        totalSinImpuestos: "20.00",
        totalDescuento: "0.00",
        totalConImpuestos: [{ codigo: "2", codigoPorcentaje: "4", baseImponible: "20.00", valor: "3.00" }],
        propina: "0.00",
        importeTotal: "23.00",
        pagos: [{ formaPago: "01", total: "23.00" }],
      },
      detalles: [{
        codigoPrincipal: "P001",
        descripcion: "Producto de prueba",
        cantidad: "2",
        precioUnitario: "10.00",
        descuento: "0.00",
        precioTotalSinImpuesto: "20.00",
        impuestos: [{ codigo: "2", codigoPorcentaje: "4", tarifa: "15", baseImponible: "20.00", valor: "3.00" }],
      }],
      infoAdicional: [{ nombre: "Email", valor: "cliente@example.com" }],
    };
  }

  $("invoice").value = JSON.stringify(example(), null, 2);
  loadConfig();
})();
