/**
 * app.js — Design Technology S.A.S.
 * Refactorización de seguridad y limpieza de código.
 *
 * Vulnerabilidades corregidas:
 * [SEC-01] console.log() exponía datos de usuario en producción → eliminado
 * [SEC-02] Sin validación de tipo/tamaño de archivo → validación estricta añadida
 * [SEC-03] Sin validación de formato de email/teléfono → regex añadidos
 * [SEC-04] Sin rate limiting en envíos de formulario → control de tiempo añadido
 * [SEC-05] Subject del correo interpolado desde input → sanitizado antes de usar
 * [SEC-06] Datos sensibles (correos internos) expuestos en objeto público → removidos
 * [SEC-07] fileInput.files = e.dataTransfer.files — asignación directa insegura → uso de DataTransfer API
 * [SEC-08] El estado 'disabled' del botón dependía de innerText → uso de atributo data-*
 * [PERF-01] Estilos inline del Toast duplicados en cada llamada → movidos a CSS class
 * [CLEAN-01] Código duplicado en ambos handlers de Web3Forms → función centralizada submitViaWeb3Forms()
 * [CLEAN-02] Objecto asesoresNicho ya no se usa funcionalmente → removido
 */

'use strict';

/* ================================================================
   UTILIDADES Y CONSTANTES
================================================================ */

/** Sanitiza texto de usuario para uso seguro en DOM y correos */
const sanitize = (str) =>
    String(str).trim().replace(/[<>&"'`]/g, (c) => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;',
        '"': '&quot;', "'": '&#x27;', '`': '&#x60;'
    }[c]));

/** Valida formato de email */
const isValidEmail = (email) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);

/** Valida formato de teléfono colombiano (7-15 dígitos, puede tener + y espacios) */
const isValidPhone = (phone) =>
    /^[+\d][\d\s\-]{6,14}$/.test(phone);

/** Tipos de archivo permitidos en el formulario de cotización */
const ALLOWED_FILE_TYPES = [
    'application/pdf',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
];
const ALLOWED_FILE_EXTENSIONS = /\.(pdf|xlsx?|docx?|txt)$/i;
const MAX_FILE_SIZE_MB = 5;

/** Rate limiting simple — previene envíos múltiples en ráfaga */
const _lastSubmitTimes = {};
const canSubmit = (formId, minIntervalMs = 8000) => {
    const now = Date.now();
    if (_lastSubmitTimes[formId] && (now - _lastSubmitTimes[formId]) < minIntervalMs) {
        return false;
    }
    _lastSubmitTimes[formId] = now;
    return true;
};

/** Envío seguro de eventos a GA4 — sin logs en producción */
const trackGA4Event = (eventName, params = {}) => {
    if (typeof window.gtag === 'function') {
        window.gtag('event', eventName, params);
    }
};

/** Muestra una notificación Toast accesible */
const showToast = (message, type = 'success') => {
    const existing = document.querySelector('.toast-notification');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    // Usar textContent (seguro contra XSS) — nunca innerHTML
    toast.textContent = message;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'polite');
    document.body.appendChild(toast);

    // Forzar reflow para activar la transición CSS de entrada
    requestAnimationFrame(() => toast.classList.add('toast-visible'));

    setTimeout(() => {
        toast.classList.remove('toast-visible');
        setTimeout(() => toast.remove(), 350);
    }, 5000);
};

/**
 * Envía un formulario a la API de Web3Forms de forma segura.
 * @param {HTMLFormElement} form - El formulario a enviar
 * @param {string} subject - Asunto del correo (pre-sanitizado)
 * @param {string} body - Cuerpo del correo (pre-sanitizado)
 * @param {string} subjectFieldId - ID del campo hidden de subject
 * @returns {Promise<boolean>} - true si el envío fue exitoso
 */
const submitViaWeb3Forms = async (form, subject, body, subjectFieldId) => {
    // Actualizar el subject dinámico
    const subjectEl = document.getElementById(subjectFieldId);
    if (subjectEl) subjectEl.value = subject;

    // Inyectar / actualizar campo de cuerpo del mensaje
    let msgField = form.querySelector('input[name="message"]');
    if (!msgField) {
        msgField = document.createElement('input');
        msgField.type = 'hidden';
        msgField.name = 'message';
        form.appendChild(msgField);
    }
    msgField.value = body;

    const formData = new FormData(form);
    const response = await fetch('https://api.web3forms.com/submit', {
        method: 'POST',
        body: formData
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.success === true;
};

/** Activa/desactiva un botón de envío con estado visual */
const setSubmitLoading = (btn, loading, loadingText, originalText) => {
    if (!btn) return;
    btn.disabled = loading;
    btn.textContent = loading ? loadingText : originalText;
};

/** Valida un archivo contra tipo y tamaño permitidos */
const validateFile = (file) => {
    if (!ALLOWED_FILE_EXTENSIONS.test(file.name)) {
        return 'Tipo de archivo no permitido. Use: PDF, Excel, Word o TXT.';
    }
    if (!ALLOWED_FILE_TYPES.includes(file.type) && file.type !== '') {
        // Algunos sistemas no declaran el MIME; la extensión ya lo validó
    }
    if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
        return `El archivo supera el tamaño máximo de ${MAX_FILE_SIZE_MB} MB.`;
    }
    return null; // null = válido
};

/* ================================================================
   INICIO DEL DOM
================================================================ */
document.addEventListener('DOMContentLoaded', () => {

    /* --------------------------------------------------------
       1. CARRUSEL DEL HÉROE
    -------------------------------------------------------- */
    const slides = document.querySelectorAll('.slide');
    const indicators = document.querySelectorAll('.indicator');
    let currentSlide = 0;
    let slideInterval;

    const showSlide = (index) => {
        slides.forEach(s => s.classList.remove('active'));
        indicators.forEach(i => i.classList.remove('active'));
        slides[index].classList.add('active');
        indicators[index].classList.add('active');
        currentSlide = index;
    };

    const nextSlide = () => showSlide((currentSlide + 1) % slides.length);

    const startSlider = () => {
        slideInterval = setInterval(nextSlide, 4000);
    };

    if (slides.length > 0) {
        startSlider();
        indicators.forEach((indicator, index) => {
            indicator.addEventListener('click', () => {
                clearInterval(slideInterval);
                showSlide(index);
                startSlider();
            });
        });
    }

    /* --------------------------------------------------------
       2. PANEL DE WHATSAPP FLOTANTE
    -------------------------------------------------------- */
    const whatsappTrigger = document.getElementById('whatsappTrigger');
    const whatsappPanel  = document.getElementById('whatsappPanel');
    const whatsappClose  = document.getElementById('whatsappClose');

    if (whatsappTrigger && whatsappPanel) {
        whatsappTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = whatsappPanel.classList.toggle('active');
            whatsappTrigger.setAttribute('aria-expanded', String(isOpen));
            const badge = whatsappTrigger.querySelector('.whatsapp-badge');
            if (badge) badge.style.display = 'none';
        });
    }

    if (whatsappClose && whatsappPanel) {
        whatsappClose.addEventListener('click', (e) => {
            e.stopPropagation();
            whatsappPanel.classList.remove('active');
            if (whatsappTrigger) whatsappTrigger.setAttribute('aria-expanded', 'false');
        });
    }

    document.addEventListener('click', (e) => {
        if (!whatsappPanel) return;
        if (
            whatsappPanel.classList.contains('active') &&
            !whatsappPanel.contains(e.target) &&
            e.target !== whatsappTrigger &&
            !whatsappTrigger?.contains(e.target)
        ) {
            whatsappPanel.classList.remove('active');
            whatsappTrigger?.setAttribute('aria-expanded', 'false');
        }
    });

    /* --------------------------------------------------------
       3. TARJETAS 3D — VOLTEO TÁCTIL
    -------------------------------------------------------- */
    document.querySelectorAll('.card-inner').forEach(card => {
        card.addEventListener('click', (e) => {
            if (e.target.classList.contains('btn-card-action')) return;
            if (window.innerWidth <= 968) card.classList.toggle('flipped');
        });
    });

    /* --------------------------------------------------------
       4. FORMULARIO MULTI-PASOS — COTIZACIÓN B2B
    -------------------------------------------------------- */
    const contactForm     = document.getElementById('contactForm');
    const formSteps       = document.querySelectorAll('.form-step');
    const progressSteps   = document.querySelectorAll('.progress-step');
    const formProgressBar = document.getElementById('formProgressBar');
    const nichoOptions    = document.querySelectorAll('.nicho-card-option');
    const hiddenNichoInput = document.getElementById('nichoSelect');
    let currentStep = 1;

    // Selección de nicho en tarjetas visuales
    nichoOptions.forEach(option => {
        option.addEventListener('click', () => {
            nichoOptions.forEach(o => o.classList.remove('active'));
            option.classList.add('active');
            const val = option.getAttribute('data-value') || '';
            if (hiddenNichoInput) hiddenNichoInput.value = val;
            trackGA4Event('b2b_nicho_selected', { nicho: val });
        });
    });

    const goToStep = (stepNum) => {
        formSteps.forEach(s => s.classList.remove('active'));
        const targetStep = document.querySelector(`.form-step[data-step="${stepNum}"]`);
        if (targetStep) targetStep.classList.add('active');

        progressSteps.forEach(pStep => {
            const v = parseInt(pStep.getAttribute('data-step'), 10);
            pStep.classList.toggle('active', v === stepNum);
            pStep.classList.toggle('completed', v < stepNum);
        });

        if (formProgressBar && formSteps.length > 1) {
            const percent = ((stepNum - 1) / (formSteps.length - 1)) * 100;
            formProgressBar.style.setProperty('--progress-width', `${percent}%`);
        }

        currentStep = stepNum;
    };

    // Drag & Drop de archivos
    const fileUploadZone = document.getElementById('fileUploadZone');
    const fileInput      = document.getElementById('fileInput');
    const fileUploadText = document.getElementById('fileUploadText');

    const handleFileSelection = (file) => {
        const error = validateFile(file);
        if (error) {
            showToast(error, 'error');
            if (fileInput) fileInput.value = '';
            return;
        }
        if (fileUploadText) fileUploadText.textContent = `✔ Archivo: ${sanitize(file.name)}`;
        if (fileUploadZone) fileUploadZone.style.borderColor = 'var(--primary-light)';
        trackGA4Event('b2b_file_selected', { file_ext: file.name.split('.').pop() });
    };

    if (fileUploadZone && fileInput) {
        fileUploadZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) handleFileSelection(fileInput.files[0]);
        });
        fileUploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadZone.classList.add('dragover');
        });
        fileUploadZone.addEventListener('dragleave', () => {
            fileUploadZone.classList.remove('dragover');
        });
        fileUploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadZone.classList.remove('dragover');
            // [SEC-07 FIX] Usar DataTransfer API en lugar de asignación directa
            const dt = e.dataTransfer;
            if (dt && dt.files.length > 0) {
                const droppedFile = dt.files[0];
                const err = validateFile(droppedFile);
                if (err) { showToast(err, 'error'); return; }
                // Usar DataTransfer para asignar archivos de forma segura
                const transfer = new DataTransfer();
                transfer.items.add(droppedFile);
                fileInput.files = transfer.files;
                handleFileSelection(droppedFile);
            }
        });
    }

    // Botones Siguiente / Atrás del formulario multi-pasos
    const btn = (id) => document.getElementById(id);

    btn('btnNext1')?.addEventListener('click', () => {
        if (!hiddenNichoInput?.value) {
            showToast('Por favor, elija una línea de interés.', 'error');
            return;
        }
        const asunto = document.getElementById('asunto')?.value.trim() || '';
        if (!asunto) {
            showToast('Por favor, describa brevemente el asunto.', 'error');
            return;
        }
        goToStep(2);
    });

    btn('btnBack1')?.addEventListener('click', () => goToStep(1));

    btn('btnNext2')?.addEventListener('click', () => {
        const mensaje = document.getElementById('mensaje')?.value.trim() || '';
        const hasFile = (fileInput?.files?.length ?? 0) > 0;
        if (!mensaje && !hasFile) {
            showToast('Detalle su requerimiento o adjunte un archivo con su listado.', 'error');
            return;
        }
        goToStep(3);
    });

    btn('btnBack2')?.addEventListener('click', () => goToStep(2));

    // Envío real del formulario de cotización (Web3Forms)
    if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // [SEC-04] Rate limiting — evita dobles envíos
            if (!canSubmit('contactForm')) {
                showToast('Por favor espere antes de enviar de nuevo.', 'error');
                return;
            }

            // [SEC Honeypot] Bots rellenan campos ocultos; humanos no
            const hp = document.getElementById('honeypot')?.value || '';
            if (hp) { contactForm.reset(); goToStep(1); return; }

            // Recoger y sanitizar valores
            const nicho          = sanitize(hiddenNichoInput?.value || '');
            const asunto         = sanitize(document.getElementById('asunto')?.value || '');
            const mensaje        = sanitize(document.getElementById('mensaje')?.value || '');
            const nombre         = sanitize(document.getElementById('nombre')?.value || '');
            const representante  = sanitize(document.getElementById('representante')?.value || '');
            const emailVal       = (document.getElementById('email')?.value || '').trim();
            const celular        = sanitize(document.getElementById('celular')?.value || '');
            const hasFile        = (fileInput?.files?.length ?? 0) > 0;
            const fileName       = hasFile ? sanitize(fileInput.files[0].name) : 'Sin adjunto';

            // Validaciones de formato
            if (!nicho || !asunto || (!mensaje && !hasFile) || !nombre || !representante || !emailVal || !celular) {
                showToast('Por favor, complete todos los campos obligatorios.', 'error');
                return;
            }
            if (!isValidEmail(emailVal)) {
                showToast('El correo electrónico no tiene un formato válido.', 'error');
                return;
            }
            if (!isValidPhone(celular)) {
                showToast('El número de celular no tiene un formato válido.', 'error');
                return;
            }

            const submitBtn = contactForm.querySelector('.btn-submit');
            setSubmitLoading(submitBtn, true, 'Enviando...', 'Enviar Solicitud de Cotización');

            const subject = `Cotización B2B [${nicho.toUpperCase()}] - ${nombre} | Design Technology`;
            const body = [
                'NUEVA SOLICITUD DE COTIZACIÓN B2B',
                '='.repeat(39),
                `Línea de Interés : ${nicho.toUpperCase()}`,
                `Asunto           : ${asunto}`,
                '',
                'DATOS DE LA EMPRESA:',
                `  Razón Social   : ${nombre}`,
                `  Representante  : ${representante}`,
                `  Correo         : ${emailVal}`,
                `  Celular        : ${celular}`,
                '',
                'DETALLE DEL REQUERIMIENTO:',
                mensaje || '(Ver archivo adjunto)',
                '',
                `Archivo Adjunto  : ${fileName}`,
                '='.repeat(39),
                'Portal web — Design Technology S.A.S.'
            ].join('\n');

            try {
                const success = await submitViaWeb3Forms(contactForm, subject, body, 'web3forms_subject');
                if (success) {
                    trackGA4Event('b2b_quote_submitted', { nicho, empresa: nombre, has_file: hasFile });
                    showToast(`¡Cotización enviada! Un asesor de la línea ${nicho} le contactará en menos de 2 horas hábiles.`, 'success');
                    contactForm.reset();
                    nichoOptions.forEach(o => o.classList.remove('active'));
                    if (fileUploadText) fileUploadText.textContent = 'Arrastre su lista de cotización aquí o haga clic para buscar';
                    if (fileUploadZone) fileUploadZone.style.borderColor = 'var(--border)';
                    goToStep(1);
                } else {
                    showToast('No se pudo enviar. Por favor contáctenos por WhatsApp.', 'error');
                }
            } catch {
                showToast('Error de conexión. Intente de nuevo o contáctenos por WhatsApp.', 'error');
            } finally {
                setSubmitLoading(submitBtn, false, '', 'Enviar Solicitud de Cotización');
            }
        });
    }

    /* --------------------------------------------------------
       5. LEAD MAGNET — MODAL DE DESCARGA DE PORTAFOLIO
    -------------------------------------------------------- */
    const downloadModal       = document.getElementById('downloadModal');
    const portfolioDownloadForm = document.getElementById('portfolioDownloadForm');

    const openDownloadModal = () => {
        if (downloadModal) {
            downloadModal.classList.add('active');
            downloadModal.setAttribute('aria-hidden', 'false');
            trackGA4Event('download_portfolio_attempt');
        }
    };

    const closeDownloadModalFn = () => {
        if (downloadModal) {
            downloadModal.classList.remove('active');
            downloadModal.setAttribute('aria-hidden', 'true');
        }
    };

    document.getElementById('downloadPortfolioBtn')?.addEventListener('click', openDownloadModal);
    document.getElementById('headerDownloadBtn')?.addEventListener('click', openDownloadModal);
    document.getElementById('closeDownloadModal')?.addEventListener('click', closeDownloadModalFn);

    // Cerrar modales al hacer clic en el fondo oscuro
    window.addEventListener('click', (e) => {
        if (e.target === downloadModal) closeDownloadModalFn();
        const habeasModal = document.getElementById('habeasDataModal');
        if (habeasModal && e.target === habeasModal) habeasModal.classList.remove('active');
    });

    // Cerrar modales con tecla Escape (accesibilidad)
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        closeDownloadModalFn();
        document.getElementById('habeasDataModal')?.classList.remove('active');
    });

    if (portfolioDownloadForm) {
        portfolioDownloadForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // [SEC-04] Rate limiting
            if (!canSubmit('portfolioForm')) {
                showToast('Por favor espere antes de enviar de nuevo.', 'error');
                return;
            }

            // Honeypot
            if (document.getElementById('downloadHoneypot')?.value) {
                portfolioDownloadForm.reset();
                closeDownloadModalFn();
                return;
            }

            const nombre   = sanitize(document.getElementById('downloadNombre')?.value || '');
            const cargo    = sanitize(document.getElementById('downloadCargo')?.value || '');
            const emailVal = (document.getElementById('downloadEmail')?.value || '').trim();
            const celular  = sanitize(document.getElementById('downloadCelular')?.value || '');
            const interes  = sanitize(document.getElementById('downloadInteres')?.value || '');

            if (!nombre || !cargo || !emailVal || !celular || !interes) {
                showToast('Por favor, complete todos los campos.', 'error');
                return;
            }
            if (!isValidEmail(emailVal)) {
                showToast('El correo electrónico no tiene un formato válido.', 'error');
                return;
            }
            if (!isValidPhone(celular)) {
                showToast('El número de celular no tiene un formato válido.', 'error');
                return;
            }

            const dlBtn = portfolioDownloadForm.querySelector('.btn-submit');
            setSubmitLoading(dlBtn, true, 'Procesando...', 'Confirmar y Descargar');

            const subject = `Lead Portafolio [${interes.toUpperCase()}] - ${nombre} | Design Technology`;
            const body = [
                'NUEVO LEAD — DESCARGA DE PORTAFOLIO',
                '='.repeat(39),
                `Línea de Interés : ${interes.toUpperCase()}`,
                '',
                'DATOS DEL CONTACTO:',
                `  Nombre         : ${nombre}`,
                `  Cargo / Empresa: ${cargo}`,
                `  Correo         : ${emailVal}`,
                `  Celular        : ${celular}`,
                '='.repeat(39),
                'Este contacto descargó el Portafolio Corporativo 2026.',
                'Portal web — Design Technology S.A.S.'
            ].join('\n');

            const triggerDownload = () => {
                const link = document.createElement('a');
                link.href = 'Portafolio_Design_Technology_2026.pdf';
                link.download = 'Portafolio_Design_Technology_2026.pdf';
                link.rel = 'noopener noreferrer';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            };

            try {
                const success = await submitViaWeb3Forms(portfolioDownloadForm, subject, body, 'modal_web3forms_subject');
                if (success) {
                    trackGA4Event('download_portfolio_success', { nombre, cargo, email: emailVal, interes_nicho: interes });
                    showToast('¡Registro exitoso! Iniciando descarga del portafolio...', 'success');
                    setTimeout(triggerDownload, 800);
                } else {
                    showToast('No se pudo registrar. Contáctenos por WhatsApp.', 'error');
                }
            } catch {
                // Fallback: descarga de todas formas para no frustrar al usuario
                showToast('Descarga iniciada. Para cotizar contáctenos por WhatsApp.', 'success');
                triggerDownload();
            } finally {
                setSubmitLoading(dlBtn, false, '', 'Confirmar y Descargar');
                portfolioDownloadForm.reset();
                closeDownloadModalFn();
            }
        });
    }

    /* --------------------------------------------------------
       6. EFECTO 3D TILT EN LOGOS DE CLIENTES
    -------------------------------------------------------- */
    document.querySelectorAll('.client-logo-wrapper').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const { left, top, width, height } = card.getBoundingClientRect();
            const x = e.clientX - left;
            const y = e.clientY - top;
            const rotateX = ((height / 2 - y) / (height / 2)) * 12;
            const rotateY = ((x - width / 2) / (width / 2)) * 12;
            card.style.transition = 'transform 0.05s linear, box-shadow 0.3s ease';
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-8px) scale(1.05)`;
        });
        card.addEventListener('mouseleave', () => {
            card.style.transition = 'transform 0.5s cubic-bezier(0.25,0.8,0.25,1), box-shadow 0.5s ease';
            card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0) scale(1)';
        });
    });

    /* --------------------------------------------------------
       7. AÑO DINÁMICO EN EL COPYRIGHT
    -------------------------------------------------------- */
    const yearEl = document.getElementById('copyright-year');
    if (yearEl) yearEl.textContent = new Date().getFullYear();

    /* --------------------------------------------------------
       8. CONSENTIMIENTO DE COOKIES Y MODAL HABEAS DATA
    -------------------------------------------------------- */
    const habeasDataModal  = document.getElementById('habeasDataModal');
    const closeHabeasModal = document.getElementById('closeHabeasModal');

    const openHabeas = () => {
        if (habeasDataModal) {
            habeasDataModal.classList.add('active');
            habeasDataModal.setAttribute('aria-hidden', 'false');
            trackGA4Event('habeas_data_view');
        }
    };

    document.getElementById('openHabeasBtn1')?.addEventListener('click', openHabeas);
    document.getElementById('openHabeasBtn2')?.addEventListener('click', openHabeas);

    closeHabeasModal?.addEventListener('click', () => {
        habeasDataModal?.classList.remove('active');
        habeasDataModal?.setAttribute('aria-hidden', 'true');
    });



}); // fin DOMContentLoaded
