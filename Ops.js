// Facilities data with allocation tracking
const facilities = [
    { id: 1, name: "Tsetse Clinic", type: "Clinic", area: "Mahikeng", contact: "Sister Bathebeng", phone: "0732998540", allocations: 0, visits: [], consentForms: 0 },
    { id: 2, name: "Nursing College", type: "School", area: "Mahikeng", contact: "Lerato", phone: "0611621466", allocations: 0, visits: [], consentForms: 0 },
    { id: 3, name: "Naledi SAPS", type: "Police Station", area: "Naledi", contact: "Captain Mosia", phone: "0795042442", allocations: 0, visits: [], consentForms: 0 },
    { id: 4, name: "Lonehill Fire Station", type: "Government", area: "Sandton", contact: "Patricia", phone: "0113755911", allocations: 0, visits: [], consentForms: 0 },
    { id: 5, name: "Wendywood Clinic", type: "Clinic", area: "Sandton", contact: "Grace", phone: "0814950127", allocations: 0, visits: [], consentForms: 0 },
    { id: 6, name: "Petervale Clinic", type: "Clinic", area: "Sandton", contact: "Thokozane", phone: "0780066915", allocations: 0, visits: [], consentForms: 0 },
    { id: 7, name: "Edenvale Clinic", type: "Clinic", area: "Sandton", contact: "Mbali", phone: "0849066447", allocations: 0, visits: [], consentForms: 0 },
    { id: 8, name: "Bree Primary School", type: "School", area: "Joburg", contact: "Ms S Mohamed", phone: "0681553039", allocations: 0, visits: [], consentForms: 0 },
    { id: 9, name: "JHB Central SAPS", type: "Police Station", area: "Joburg", contact: "Mr Kubayi", phone: "011497000", allocations: 0, visits: [], consentForms: 0 },
    { id: 10, name: "Osizweni Clinic", type: "Clinic", area: "Evaton", contact: "Mr Motsamai", phone: "0796791207", allocations: 0, visits: [], consentForms: 0 },
    { id: 11, name: "DR KUHN Clinic", type: "Clinic", area: "Palm Springs", contact: "Facility Manager", phone: "0165810021", allocations: 0, visits: [], consentForms: 0 },
    { id: 12, name: "Montshioa Clinic", type: "Clinic", area: "Mafikeng", contact: "T. P Mogobere", phone: "0183840926", allocations: 0, visits: [], consentForms: 0 },
    { id: 13, name: "Florida Primary", type: "School", area: "Florida", contact: "Mrs J Whittaker", phone: "0114723552", allocations: 0, visits: [], consentForms: 0 },
    { id: 14, name: "JST Hospital Emergency", type: "Hospital", area: "Rustenburg", contact: "Manager", phone: "0714123244", allocations: 0, visits: [], consentForms: 0 },
    { id: 15, name: "Rabasotho Combined School", type: "School", area: "Diepsloot", contact: "Mr Matosa", phone: "0635237923", allocations: 0, visits: [], consentForms: 0 },
    { id: 16, name: "Westview Clinic", type: "Clinic", area: "Florida", contact: "A. Barriel", phone: "0614398957", allocations: 0, visits: [], consentForms: 0 },
    { id: 17, name: "Florida High School", type: "School", area: "Florida", contact: "Mr Mmutlane", phone: "0114971247", allocations: 0, visits: [], consentForms: 0 },
    { id: 18, name: "Thembisa West Secondary", type: "School", area: "Tembisa", contact: "Mr Seleho", phone: "0110568241", allocations: 0, visits: [], consentForms: 0 },
    { id: 19, name: "Oliven SAPS", type: "Police Station", area: "Oliven", contact: "Mr Dladla", phone: "0126520082", allocations: 0, visits: [], consentForms: 0 },
    { id: 20, name: "Phuthang Clinic", type: "Clinic", area: "Brakpan", contact: "Nkgopotse", phone: "0711639085", allocations: 0, visits: [], consentForms: 0 },
    { id: 21, name: "Kanana Clinic", type: "Clinic", area: "Brakpan", contact: "Sister Thandi", phone: "0737373460", allocations: 0, visits: [], consentForms: 0 },
    { id: 22, name: "Rustenburg Magistrate Court", type: "Government", area: "Rustenburg", contact: "Manager", phone: "0824030501", allocations: 0, visits: [], consentForms: 0 },
    { id: 23, name: "Winnie Mandela Clinic", type: "Clinic", area: "Eastrand", contact: "Mokoena", phone: "N/A", allocations: 0, visits: [], consentForms: 0 },
    { id: 24, name: "Phomolong Clinic", type: "Clinic", area: "Eastrand", contact: "Jerky", phone: "N/A", allocations: 0, visits: [], consentForms: 0 },
    { id: 25, name: "Klipriver SAPS", type: "Police Station", area: "Eastrand", contact: "Col Mofokeng", phone: "0827787898", allocations: 0, visits: [], consentForms: 0 },
    { id: 26, name: "Benoni Police Station", type: "Police Station", area: "Eastrand", contact: "Captain", phone: "0117470230", allocations: 0, visits: [], consentForms: 0 },
    { id: 27, name: "Silverkraans Clinic", type: "Clinic", area: "Rustenburg", contact: "Mrs Noni", phone: "0712783294", allocations: 0, visits: [], consentForms: 0 },
    { id: 28, name: "Mose Kotane Hospital", type: "Hospital", area: "Rustenburg", contact: "Mrs Nthabiseng", phone: "0663088456", allocations: 0, visits: [], consentForms: 0 },
    { id: 29, name: "Meadowlands High School", type: "School", area: "Meadowlands", contact: "Ofentse Seku", phone: "0825575101", allocations: 0, visits: [], consentForms: 0 },
    { id: 30, name: "Dayton Main Clinic", type: "Clinic", area: "Dayveton", contact: "Mr Dube", phone: "0119990345", allocations: 0, visits: [], consentForms: 0 },
    { id: 31, name: "Adam Masebe Tshwane North", type: "School", area: "Sekempaneng Secondary", contact: "Receptionist", phone: "0615487903", allocations: 0, visits: [], consentForms: 0 },
    { id: 32, name: "Albertina Sisulu Ekurhuleni", type: "School", area: "Kingsway, Primary North Benoni", contact: "Receptionist", phone: "0114233371", allocations: 0, visits: [], consentForms: 0 },
    { id: 33, name: "Altmont Tech High Johannesburg", type: "School", area: "Soweto", contact: "Receptionist", phone: "0119802226", allocations: 0, visits: [], consentForms: 0 },
    { id: 34, name: "Asser Maloka Sec Gauteng East", type: "School", area: "Nigel", contact: "Receptionist", phone: "0105160759", allocations: 0, visits: [], consentForms: 0 },
    { id: 35, name: "Bachana Mokwena Tshwane East", type: "School", area: "Ga-Rankuwa, Prima PTA", contact: "Receptionist", phone: "0127003017", allocations: 0, visits: [], consentForms: 0 },
    { id: 36, name: "Barcelona Primary Ekurhuleni", type: "School", area: "Daveyton North", contact: "Receptionist", phone: "0819709199", allocations: 0, visits: [], consentForms: 0 },
    { id: 37, name: "Barrage Primary Sedibeng", type: "School", area: "Vanderbijlpark Farm School West", contact: "Receptionist", phone: "0169871787", allocations: 0, visits: [], consentForms: 0 },
    { id: 38, name: "Bathabile Primary Tshwane", type: "School", area: "Centurion Farm School South", contact: "Receptionist", phone: "0126523893", allocations: 0, visits: [], consentForms: 0 },
    { id: 39, name: "Hoerskool Birchleigh Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119725415", allocations: 0, visits: [], consentForms: 0 },
    { id: 40, name: "Benoni High School Ekurhuleni", type: "School", area: "Benoni North", contact: "Receptionist", phone: "0118494129", allocations: 0, visits: [], consentForms: 0 },
    { id: 41, name: "Hoerskool Hans Ekurhuleni", type: "School", area: "Benoni Moore North", contact: "Receptionist", phone: "0114251007", allocations: 0, visits: [], consentForms: 0 },
    { id: 42, name: "Crystal Park High Ekurhuleni", type: "School", area: "Crystal Park School North", contact: "Receptionist", phone: "0119693531", allocations: 0, visits: [], consentForms: 0 },
    { id: 43, name: "Gekombineerde Ekurhuleni", type: "School", area: "Benoni Skool Noordelig North", contact: "Receptionist", phone: "0119689931", allocations: 0, visits: [], consentForms: 0 },
    { id: 44, name: "Unity Secondary Ekurhuleni", type: "School", area: "Daveyton School North", contact: "Receptionist", phone: "0114241471", allocations: 0, visits: [], consentForms: 0 },
    { id: 45, name: "Norkem Park High Ekurhuleni East", type: "School", area: "Norkem Park School", contact: "Receptionist", phone: "0119724144", allocations: 0, visits: [], consentForms: 0 },
    { id: 46, name: "Mooifontein Primary Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119761030", allocations: 0, visits: [], consentForms: 0 },
    { id: 47, name: "Kempton Park Ekurhuleni East", type: "School", area: "Kempton Park Primary", contact: "Receptionist", phone: "0165838087", allocations: 0, visits: [], consentForms: 0 },
    { id: 48, name: "Sir Pierre High School Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119701811", allocations: 0, visits: [], consentForms: 0 },
    { id: 49, name: "Rhodesfield High Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119701229", allocations: 0, visits: [], consentForms: 0 },
    { id: 50, name: "Hoerskool Kempton Ekurhuleni East", type: "School", area: "Kempton Park Park", contact: "Receptionist", phone: "0119702102", allocations: 0, visits: [], consentForms: 0 },
    { id: 51, name: "Hoerskool Jeugland Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119763038", allocations: 0, visits: [], consentForms: 0 },
    { id: 52, name: "Laerskool Kreft Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119701320", allocations: 0, visits: [], consentForms: 0 },
    { id: 53, name: "Laerskool Kempton Ekurhuleni East", type: "School", area: "Kempton Park Park", contact: "Receptionist", phone: "0119752312", allocations: 0, visits: [], consentForms: 0 },
    { id: 54, name: "Aston Manor Primary Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119702171", allocations: 0, visits: [], consentForms: 0 },
    { id: 55, name: "Laerskool Van Ekurhuleni East", type: "School", area: "Kempton Park Riebeck", contact: "Receptionist", phone: "0119762633", allocations: 0, visits: [], consentForms: 0 },
    { id: 56, name: "Laerskool Birchleigh Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119722127", allocations: 0, visits: [], consentForms: 0 },
    { id: 57, name: "Laerskool Edleen Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119761033", allocations: 0, visits: [], consentForms: 0 },
    { id: 58, name: "Petit High School Ekurhuleni", type: "School", area: "Daveyton North", contact: "Receptionist", phone: "0119560788", allocations: 0, visits: [], consentForms: 0 },
    { id: 59, name: "Dinoto Tech Sec Ekurhuleni", type: "School", area: "Daveyton North", contact: "Receptionist", phone: "0825546163", allocations: 0, visits: [], consentForms: 0 },
    { id: 60, name: "Crystal Park Primary Ekurhuleni", type: "School", area: "Crystal Park North", contact: "Receptionist", phone: "0119693608", allocations: 0, visits: [], consentForms: 0 },
    { id: 61, name: "Norkem Park Primary Ekurhuleni East", type: "School", area: "Kempton Park", contact: "Receptionist", phone: "0119724211", allocations: 0, visits: [], consentForms: 0 },
    { id: 62, name: "Parktown Girls Joburg North", type: "School", area: "Parkview", contact: "Receptionist", phone: "0115935900", allocations: 0, visits: [], consentForms: 0 },
    { id: 63, name: "Greenside High Joburg North", type: "School", area: "Greenside", contact: "Receptionist", phone: "0116460113", allocations: 0, visits: [], consentForms: 0 }
];

// 2026 spreadsheet additions - unrestricted (available any weekday)
const unrestrictedFacilities2026 = `
Education
Military Base MHK
Social Development unit 2
Mocogeng Clinic
Madibe Makgabane Clinic
Lekoko Clinic
Magogoe Clinic
Lokaleng Clinic
Tsumbedzo primary school
Mncube High school
Discovery Clinic
Mogosane Clinic
Dept. Of Agriculture
Montshioa Station
Thathezakho primary school
JST hospital emergency section
Musenga Vadhadzimu P.School
Lekoko Primary School
Home Affairs
B. M Mokitime Primary School
St. Mary Primary School
St. Mary Secondary School
Unified primary school
Rustenburg Magesrate court
Tlhabane Magestrate court
Benoni flying squard
SAPS Uniform Shop
SAPS Provincial Archives
SAPS GARAGE
SAPS Radio Tech
SAPS POP
Emergency JST hospital
Esiyalwini primary school
Meadowlands primary school
Anchor High school
Ipeleng Primary School
D.P kgotlheng Primary School
Education unit 1
Motladi Kgoadigoadi P school
Rauweng Sepeng H school
Boitekong health care
Mabeskraal clinic
Masiqhakaze S.School
Bapedi primary school
Tembisa West S.School
Orlando high school
Zitikeni S.School
Marhulana P.School
Jiyana S.School
Danville Secondary School
Danville Primary School
J. M Mosiane Primary School
Seetsele Primary School
Letlamoreng Primary School
Crystal park clinic
Police station
Nicely Primary school
Dawn Park primary
Windmill Patk
Bafokeng Health care
H F Tlou High school
JD Mosia Primary School
President Mangope Tech High School
Kgatseng Thabiso High School
STATS SA
Morutathuto primary school
Mokgome High school
Hlabengane primary school
Rebongwe primary school
Kwa-Mahlobo
Thutolore high school
Livhuwani primary school
W, K Maponyane primary school
Theresa Park P.School
Morongwa P School
Theresa park S.School
Amandasing S.School
Bogatsu P School
Orchards P.School
Saron P School
Matale Sec School
Mokalake P School
Thakadu P School
Motlhaputseng Sec School
Rosslyn P.School
Leteane Secondary School
Senkgwe Primary School
Senkgwe Middle School
Tshidi-Barolong Secondary School
Ramaine A Phetlhu Secondary
Amandasig S.School
Wk Mapanyane
Livhuwani primary schools
Kwa-Mahlobo high school
Khensani P.School
Ubuhle Bezwe P.School
Hlomphanang S.School
Tshabelopele PS
Rutanang PS
Karabelo PS
Public work's
GLEN AGRICULTURE COLLEGE
Rekgone PS
MUCCP CLINIC
Sehunelo s.s
Madibe Combine School
Tswelelopele High School
Sejankabo High School
`.trim().split('\n').map((n) => n.trim()).filter(Boolean);

const allocationFacilities = [
    { name: "Charlotte Maxeke Hospital", type: "Hospital", location: "Parktown", days: "Mondays", status: "Active" },
    { name: "Betha Xhowa Hospital", type: "Hospital", location: "Germiston", days: "Tue/Thur", status: "Active" },
    { name: "Telle Mogwerane Hospital", type: "Hospital", location: "Vosloorus", days: "Tues/thur", status: "Active" },
    { name: "Far East Hospital", type: "Hospital", location: "Brakpan", days: "Daily", status: "Active" },
    { name: "OR Tambo Memorial Hospital", type: "Hospital", location: "Boksburg", days: "Tueday", status: "Active" },
    { name: "Kalafong Hospital", type: "Hospital", location: "Pretoria", days: "Tues/thur", status: "Active" },
    { name: "Kopanong Hospital", type: "Hospital", location: "Pretoria", days: "Wed/thu/fri", status: "Active" },
    { name: "Chris Hani Bara Hospital", type: "Hospital", location: "Soweto", days: "Daily", status: "Active" },
    { name: "Boksburg Prison", type: "Prison", location: "Boksburg", days: "Pending", status: "" },
    { name: "Carltonville Hospital", type: "Hospital", location: "Carltonville", days: "Mondays", status: "Active" },
    { name: "Leratong Hospital", type: "Hospital", location: "Randfontein", days: "Daily", status: "Active" },
    { name: "Helen Joseph Hospital", type: "Hospital", location: "Johannesburg", days: "Daily", status: "Active" },
    { name: "Yussif Dadoo Hospital", type: "Hospital", location: "Krugersdorp", days: "Thur/fri", status: "Active" },
    { name: "Tara Hospital", type: "Hospital", location: "Sandton", days: "Mondays", status: "Active" },
    { name: "Rahima Moosa Hospital", type: "Hospital", location: "Johannesburg", days: "Tues/thu", status: "Active" },
    { name: "Pholosong Hospital", type: "Hospital", location: "Brakpan", days: "Tuesdays", status: "Active" },
    { name: "Sebokeng Hospital", type: "Hospital", location: "Sebokeng", days: "Daily", status: "Active" },
    { name: "Edenvale Hospital", type: "Hospital", location: "Edenvale", days: "Mondays", status: "Active" },
    { name: "Sizwe Hospital", type: "Hospital", location: "Johannesburg", days: "Pending", status: "" },
    { name: "Sun City Prison", type: "Prison", location: "Johannesburg", days: "Daily", status: "Active" },
    { name: "Modderbee Prison", type: "Prison", location: "Daveyton", days: "Daily", status: "Chris" },
    { name: "Kgosi Mampuru Prison", type: "Prison", location: "Pretoria", days: "Pending", status: "" },
    { name: "George Mukhari Hospital", type: "Hospital", location: "Pretoria", days: "Pending", status: "" }
];

const allocationFacilityNames = new Set(
    allocationFacilities.map((f) => normalizeFacilityName(expandFacilityName(f.name)))
);
const DEFAULT_BROKER_AUTHORITY_CODE = 'BA-2026-MLI';

// Configuration constants - all magic numbers centralized here
const CONFIG = {
    // Facility settings
    MAX_ALLOCATIONS: 5,
    FACILITY_PAGE_SIZE: 50,
    AVAILABLE_TODAY_LIMIT: 12,
    
    // Timing (milliseconds)
    DEBOUNCE_DELAY: 150,
    STORAGE_WRITE_DELAY: 150,
    TOAST_DURATION: 2800,
    TOAST_FADE_DURATION: 200,
    PAGE_TRANSITION_DURATION: 320,
    PAGE_TRANSITION_FAST: 80,
    PAGE_TRANSITION_SLOW: 140,
    ANIMATION_OVERLAY_DURATION: 340,
    ANIMATION_DURATION: 500,
    BUTTON_PRESS_REMOVAL: 220,
    BUTTON_RIPPLE_REMOVAL: 360,
    THEME_TRANSITION: 480,
    FOCUS_TIMEOUT: 90,
    GEOLOCATION_TIMEOUT: 8500,
    GEOLOCATION_OPTIONS_TIMEOUT: 8000,
    GEOLOCATION_MAX_AGE: 600000,
    GEOLOCATION_REUSE_WINDOW: 120000,
    DAY_BOUNDARY_CHECK_INTERVAL: 30000,
    PARTICLE_ANIMATION_DURATION: 10,
    PARTICLE_ANIMATION_VARIANCE: 8,
    
    // Numeric limits
    MENU_TOP_SCROLL_THRESHOLD: 200,
    AUDIO_CUTOFF_TIME: 1500,
    MAX_FORM_VISIBILTY: 3,
    MIN_BAR_HEIGHT: 6,
    MASK_MIN_LENGTH: 3,
    AUDIT_LOG_MAX: 200,
    WEEKLY_ARCHIVE_MAX: 12,
    PROFILE_NAME_MAX: 100,
    FACILITY_NAME_MAX: 80,
    ADDRESS_SUMMARY_PARTS: 2,
    VISIBLE_PREFIX_MASK: 2,
    VISIBLE_SUFFIX_MASK: 2,
    
    // Daily targets
    DAILY_TARGET: 2,
    WEEKLY_TARGET: 10,
    MONTHLY_TARGET: 40,
    
    // Day offsets for transitions
    PAGE_TRANSITION_OFFSET_EARLY: 60,
    PAGE_TRANSITION_OFFSET_LATE: 170,
    
    // Search context
    SEARCH_CONTEXT_BEFORE: 60,
    SEARCH_CONTEXT_AFTER: 60
};

function safeJsonParse(raw, fallback) {
    try {
        const parsed = JSON.parse(raw);
        return parsed ?? fallback;
    } catch (_) {
        return fallback;
    }
}

function getStorageJson(key, fallback) {
    return safeJsonParse(localStorage.getItem(key), fallback);
}

const LEAD_ID_LOCK_KEY = 'leadIdLock';
const LEAD_ID_LOCK_TTL_MS = 3500;

async function withLeadIdLock(fn) {
    const token = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const start = Date.now();
    while ((Date.now() - start) < LEAD_ID_LOCK_TTL_MS) {
        const active = getStorageJson(LEAD_ID_LOCK_KEY, null);
        const now = Date.now();
        const stale = !active || !Number.isFinite(active.expiresAt) || active.expiresAt <= now;
        if (stale) {
            localStorage.setItem(LEAD_ID_LOCK_KEY, JSON.stringify({ token, expiresAt: now + LEAD_ID_LOCK_TTL_MS }));
            const check = getStorageJson(LEAD_ID_LOCK_KEY, null);
            if (check?.token === token) {
                try {
                    return await fn();
                } finally {
                    const latest = getStorageJson(LEAD_ID_LOCK_KEY, null);
                    if (latest?.token === token) {
                        localStorage.removeItem(LEAD_ID_LOCK_KEY);
                    }
                }
            }
        }
        await new Promise((resolve) => setTimeout(resolve, 80));
    }
    return fn();
}

function generateLeadId(existingIds = new Set()) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const maxAttempts = 4000;
    const activeIds = new Set(
        [...(existingIds || new Set()), ...usedLeadIds]
            .map((id) => String(id || '').trim().toUpperCase())
            .filter(Boolean)
    );
    const randomBytes = (length) => {
        if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
            const out = new Uint8Array(length);
            window.crypto.getRandomValues(out);
            return out;
        }
        return Array.from({ length }, () => Math.floor(Math.random() * 256));
    };
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        let id = '';
        const bytes = randomBytes(8);
        for (let i = 0; i < 8; i++) {
            const index = bytes[i] % chars.length;
            id += chars[index];
        }
        const formatted = `${id.slice(0, 4)}-${id.slice(4)}`.toUpperCase();
        if (!activeIds.has(formatted)) {
            usedLeadIds.add(formatted);
            try {
                localStorage.setItem(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            } catch (_) {
                // fallback handled by scheduled write below
            }
            scheduleStorageWrite(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            return formatted;
        }
    }
    let seed = `${Date.now()}-${Math.random()}-${performance.now?.() || 0}`;
    for (let guard = 0; guard < 100000; guard++) {
        let hash = 0;
        seed = `${seed}:${guard}`;
        for (let i = 0; i < seed.length; i++) {
            hash = ((hash << 5) - hash) + seed.charCodeAt(i);
            hash |= 0;
        }
        let raw = '';
        let value = Math.abs(hash);
        for (let i = 0; i < 8; i++) {
            raw += chars[value % chars.length];
            value = Math.floor(value / chars.length) || (value + i + 17);
        }
        const formatted = `${raw.slice(0, 4)}-${raw.slice(4)}`.toUpperCase();
        if (!activeIds.has(formatted)) {
            usedLeadIds.add(formatted);
            try {
                localStorage.setItem(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            } catch (_) {
                // fallback handled by scheduled write below
            }
            scheduleStorageWrite(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            return formatted;
        }
    }
    for (let i = 0; i < 10000; i++) {
        const tail = String((Date.now() + i) % 10000).padStart(4, '0');
        const candidate = `ZZZZ-${tail}`.toUpperCase();
        if (!activeIds.has(candidate)) {
            usedLeadIds.add(candidate);
            try {
                localStorage.setItem(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            } catch (_) {
                // fallback handled by scheduled write below
            }
            scheduleStorageWrite(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
            return candidate;
        }
    }
    throw new Error('Unable to allocate a unique LID.');
}

async function allocateUniqueLeadId() {
    return withLeadIdLock(async () => {
        for (let attempt = 0; attempt < 25; attempt++) {
            const storageLeads = getStorageJson(STORAGE_KEYS.leads, []);
            let remoteLeads = [];
            if (isRemoteSyncAllowed() && navigator.onLine) {
                try {
                    if (await refreshRemoteAccessTokenIfNeeded()) {
                        const response = await fetch(`${REMOTE_API_BASE}/api/state/load?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
                            headers: buildRemoteHeaders()
                        });
                        if (response.ok) {
                            const data = await response.json().catch(() => ({}));
                            const payload = data?.payload && typeof data.payload === 'object' ? data.payload : null;
                            if (payload && payload[STORAGE_KEYS.leads]) {
                                const parsed = safeJsonParse(String(payload[STORAGE_KEYS.leads]), []);
                                if (Array.isArray(parsed)) remoteLeads = parsed;
                            }
                        }
                    }
                } catch (_) {
                    // continue with local sources only
                }
            }
            const existingIds = new Set([
                ...leadRecords.map((lead) => String(lead?.leadId || '').trim().toUpperCase()).filter(Boolean),
                ...storageLeads.map((lead) => String(lead?.leadId || '').trim().toUpperCase()).filter(Boolean),
                ...remoteLeads.map((lead) => String(lead?.leadId || '').trim().toUpperCase()).filter(Boolean),
                ...[...usedLeadIds].map((id) => String(id || '').trim().toUpperCase()).filter(Boolean)
            ]);
            const next = generateLeadId(existingIds);
            if (!existingIds.has(next)) return next;
        }
        throw new Error('Unable to allocate a unique LID right now.');
    });
}

const LEAD_STATUS_OPTIONS = ['New', 'Contacted', 'Quote', 'Closed', 'Lost'];

function normalizeLeadStatus(value = '') {
    const normalized = String(value || '').trim();
    if (LEAD_STATUS_OPTIONS.includes(normalized)) return normalized;
    return 'New';
}

const PAYMENT_STATUS_OPTIONS = ['Pending', 'Unsuccessful', 'Successful'];

function normalizePaymentStatus(value = '') {
    const normalized = String(value || '').trim();
    if (PAYMENT_STATUS_OPTIONS.includes(normalized)) return normalized;
    return 'Pending';
}

function normalizeLeadText(value = '') {
    return String(value || '')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
}

function getAuditActorLabel() {
    const username = formatJfaName(appUser || '') || 'System';
    const role = adminRole || 'PERSONAL';
    const team = adminTeam ? `/${adminTeam}` : '';
    return `${username} (${role}${team})`;
}

function findDuplicateLeadSubmission(identity, clientName, clientId, clientCell) {
    const owner = normalizeJfaName(identity?.name || '');
    if (!owner) return null;
    const normalizedId = String(clientId || '').trim();
    const normalizedCell = String(clientCell || '').replace(/\D/g, '');
    const normalizedName = normalizeLeadText(clientName);
    const windowMs = 24 * 60 * 60 * 1000;
    const now = Date.now();
    return leadRecords.find((lead) => {
        if (normalizeJfaName(lead?.jfaName || '') !== owner) return false;
        const ts = new Date(lead?.timestamp || 0).getTime();
        if (!Number.isFinite(ts) || (now - ts) > windowMs) return false;
        const existingId = String(lead?.clientIdRaw || '').trim();
        if (normalizedId && existingId && normalizedId === existingId) return true;
        const existingCell = String(lead?.clientCellRaw || '').replace(/\D/g, '');
        const existingName = normalizeLeadText(lead?.clientNameRaw || lead?.clientName || '');
        return Boolean(
            normalizedCell &&
            existingCell &&
            normalizedName &&
            existingName &&
            normalizedCell === existingCell &&
            normalizedName === existingName
        );
    }) || null;
}

function sanitizeLeadForNonAdmin(lead) {
    if (!lead || typeof lead !== 'object') return lead;
    return {
        ...lead,
        clientNameRaw: '',
        clientIdRaw: '',
        clientPersalRaw: '',
        clientAddressRaw: '',
        clientCellRaw: '',
        clientHomeRaw: '',
        clientEmailRaw: '',
        authorizedIdRaw: '',
        authorizedEmailRaw: '',
        clientSignatureImage: ''
    };
}

const PAGE_FLOW_ORDER = [
    'landing-page',
    'registration-page',
    'assignment-page',
    'dbd-page',
    'stats-page',
    'admin-standalone-page',
    'archives-page'
];

function triggerButtonRipple(button, event) {
    if (!button) return;
    if (button.disabled || button.getAttribute('aria-disabled') === 'true') return;
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    button.classList.add('is-pressed');
    button.classList.add('is-fading');
    setTimeout(() => button.classList.remove('is-pressed'), 90);
    setTimeout(() => button.classList.remove('is-fading'), 180);
}

function findInteractiveTarget(element) {
    if (!(element instanceof Element)) return null;
    return element.closest('button, a.action-btn, a.submit-btn, a.back-btn, .sidebar-toggle, .sidebar-sub-btn, .sidebar-settings-btn, .sidebar-signout-btn, .nav-notification-btn, .copy-btn, .link-btn');
}

document.addEventListener('pointerdown', (event) => {
    const target = event.target;
    const interactive = findInteractiveTarget(target);
    if (!interactive) return;
    triggerButtonRipple(interactive, event);
}, true);

// Maintain backward compatibility with old constants
const MAX_ALLOCATIONS = CONFIG.MAX_ALLOCATIONS;
const MIN_AUTO_ASSIGNMENT_GROUP_SIZE = 3;
const FACILITY_PAGE_SIZE = CONFIG.FACILITY_PAGE_SIZE;
const storageWriteQueue = new Map();
let facilitiesById = new Map();
const STORAGE_KEYS = {
    records: 'jfaRecords',
    facilities: 'facilityStats',
    archives: 'jfaArchives',
    lastReset: 'jfaLastResetDate',
    dbdDraft: 'dbdDraft',
    customFacilities: 'customFacilities',
    lastDbd: 'lastDbd',
    resetTime: 'resetTime',
    theme: 'theme',
    sessionLockEnabled: 'sessionLockEnabled',
    sessionLocked: 'sessionLocked',
    currentJfa: 'currentJfa',
    lastPage: 'lastPage'
    ,auditLog: 'auditLog'
    ,archivedJfas: 'archivedJfas'
    ,weeklyFeedback: 'weeklyFeedback'
    ,weeklyFeedbackArchive: 'weeklyFeedbackArchive'
    ,weeklyKey: 'weeklyKey'
    ,leads: 'leadRecords'
    ,lastJfaIdentity: 'lastJfaIdentity'
    ,jfaProfiles: 'jfaProfiles'
    ,faProfiles: 'faProfiles'
    ,notifications: 'jfaNotifications'
    ,leaderboardSnapshot: 'leaderboardSnapshot'
    ,facilityDirectory: 'facilityDirectory'
    ,disabledFacilities: 'disabledFacilities'
    ,remoteSyncAt: 'remoteSyncAt'
    ,formsLibrary: 'formsLibrary'
    ,learningOverrides: 'learningOverrides'
    ,interventions: 'interventionLog'
    ,learningQuizRecent: 'learningQuizRecent'
    ,adminPassword: 'adminPassword'
    ,userAccounts: 'jfaUserAccounts'
    ,userMgmtAudit: 'userMgmtAudit'
    ,leadDraft: 'leadDraft'
    ,registerDraft: 'registerDraft'
    ,appointments: 'jfaAppointments'
    ,usedLeadIds: 'usedLeadIds'
    ,uiPrefs: 'uiPrefs'
    ,inactivityMinutes: 'inactivityMinutes'
    ,usedUsernames: 'jfaUsedUsernames'
    ,appBuild: 'appBuild'
    ,authRememberMe: 'authRememberMe'
    ,authRememberMode: 'authRememberMode'
    ,authRememberUser: 'authRememberUser'
};

const REMOTE_API_BASE = (window.JFA_API_BASE || '').trim() || window.location.origin;
const REMOTE_API_TOKEN = (window.JFA_API_TOKEN || '').trim();
const REMOTE_STATE_SCOPE = window.JFA_DB_SCOPE || 'matla-life-default';
const SESSION_KEYS = {
    adminRole: 'adminRole',
    adminTeam: 'adminTeam',
    adminAccess: 'adminAccess',
    adminMenuAccess: 'adminMenuAccess',
    appUser: 'appUser',
    remoteAccessToken: 'remoteAccessToken',
    remoteRefreshToken: 'remoteRefreshToken',
    remoteSessionId: 'remoteSessionId',
    remoteAccessExpAt: 'remoteAccessExpAt',
    remoteRefreshExpAt: 'remoteRefreshExpAt'
};
const ADMIN_PIN = (window.JFA_ADMIN_PIN || '').trim();
const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'admin';
const APP_BUILD = '1.0.64';
const ADMIN_DEFAULT_BOOTSTRAP_MARKER = 'adminDefaultBootstrap-v1.0.64';
const FORCE_CACHE_PURGE_TOKEN = '2026-02-17-force-purge-13';
const FA_ATTENDANCE_STORAGE_KEY = 'faAttendanceRecords';
const REMOTE_SYNC_KEYS = [
    STORAGE_KEYS.records,
    STORAGE_KEYS.facilities,
    STORAGE_KEYS.archives,
    STORAGE_KEYS.lastReset,
    STORAGE_KEYS.dbdDraft,
    STORAGE_KEYS.customFacilities,
    STORAGE_KEYS.lastDbd,
    STORAGE_KEYS.resetTime,
    STORAGE_KEYS.theme,
    STORAGE_KEYS.sessionLockEnabled,
    STORAGE_KEYS.sessionLocked,
    STORAGE_KEYS.currentJfa,
    STORAGE_KEYS.lastPage,
    STORAGE_KEYS.auditLog,
    STORAGE_KEYS.archivedJfas,
    STORAGE_KEYS.weeklyFeedback,
    STORAGE_KEYS.weeklyFeedbackArchive,
    STORAGE_KEYS.weeklyKey,
    STORAGE_KEYS.leads,
    STORAGE_KEYS.lastJfaIdentity,
    STORAGE_KEYS.jfaProfiles,
    STORAGE_KEYS.faProfiles,
    STORAGE_KEYS.facilityDirectory,
    STORAGE_KEYS.disabledFacilities,
    STORAGE_KEYS.formsLibrary,
    STORAGE_KEYS.learningOverrides,
    STORAGE_KEYS.interventions,
    STORAGE_KEYS.learningQuizRecent,
    STORAGE_KEYS.adminPassword,
    STORAGE_KEYS.userAccounts,
    STORAGE_KEYS.userMgmtAudit,
    STORAGE_KEYS.registerDraft,
    STORAGE_KEYS.appointments,
    STORAGE_KEYS.usedUsernames,
    STORAGE_KEYS.usedLeadIds
];

// Session storage
let currentJFA = null;
let jfaRecords = getStorageJson(STORAGE_KEYS.records, []);
let preAssignedFacilityId = null;
let facilityRenderLimit = FACILITY_PAGE_SIZE;
let isEditingRegistration = false;
let sessionLockEnabled = localStorage.getItem(STORAGE_KEYS.sessionLockEnabled) === 'true';
let sessionLocked = localStorage.getItem(STORAGE_KEYS.sessionLocked) === 'true';
let jfaSearchTerm = '';
let adminRole = sessionStorage.getItem(SESSION_KEYS.adminRole) || 'PERSONAL';
let adminTeam = sessionStorage.getItem(SESSION_KEYS.adminTeam) || '';
const learningPageState = {};
const MENU_TOP_SCROLL_THRESHOLD = 200;
let learningSearchTerm = '';
const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
let archivedJfaNames = new Set(getStorageJson(STORAGE_KEYS.archivedJfas, []));
let dayBoundaryWatcher = null;
let summaryLiveWatcher = null;
let appointmentReminderWatcher = null;
let currentDayKey = todayKey();
let lastOnlineState = navigator.onLine;
let notificationFilterMode = 'all';
let notificationPage = 1;
let notificationSearchTerm = '';
const NOTIFICATION_PAGE_SIZE = 8;
const activeInlineDetail = { admin: null, team: null };
let availableTodayLimit = 12;
let leadRecords = getStorageJson(STORAGE_KEYS.leads, []);
let usedLeadIds = new Set(
    (getStorageJson(STORAGE_KEYS.usedLeadIds, []) || [])
        .map((id) => String(id || '').trim().toUpperCase())
        .filter(Boolean)
);
let appointmentRecords = getStorageJson(STORAGE_KEYS.appointments, []);
let jfaProfiles = getStorageJson(STORAGE_KEYS.jfaProfiles, {});
let faProfiles = getStorageJson(STORAGE_KEYS.faProfiles, {});
let faAttendanceRecords = getStorageJson(FA_ATTENDANCE_STORAGE_KEY, []);
let disabledFacilityKeys = new Set(getStorageJson(STORAGE_KEYS.disabledFacilities, []));
let adminMasterTab = 'leads';
let adminLeadFilters = {
    from: '',
    to: '',
    team: '',
    jfa: '',
    product: '',
    status: '',
    geoStatus: '',
    willOnly: false
};
let leadGeoCache = null;
let learningFiltersBound = false;
let formsLibrary = [];
const DEFAULT_TEAM_NAMES = ['Team Thando', 'Team Thato', 'Team Rhulani'];
const CORE_TEAM_LEADER_SEEDS = [
    { username: 'Thato', team: 'Team Thato', email: 'thato@matla.local', password: 'Thato@123!' },
    { username: 'Thando', team: 'Team Thando', email: 'thando@matla.local', password: 'Thando@123!' },
    { username: 'Rhulani', team: 'Team Rhulani', email: 'rhulani@matla.local', password: 'Rhulani@123!' }
];
const CORE_TEAM_LEADER_KEYS = new Set(CORE_TEAM_LEADER_SEEDS.map((entry) => normalizeJfaName(entry.username)));
let learningOverrides = getStorageJson(STORAGE_KEYS.learningOverrides, {});
let interventionLog = getStorageJson(STORAGE_KEYS.interventions, {});
let learningQuizRecent = getStorageJson(STORAGE_KEYS.learningQuizRecent, {});
let leadSignatureState = {
    ready: false,
    isDrawing: false,
    hasSignature: false,
    resizeBound: false,
    baseImageData: '',
    strokes: [],
    currentStroke: [],
    lastX: 0,
    lastY: 0
};
const learningQuizState = {};
let pendingAdminAccessAction = null;
let pendingAdminAllAccessAction = null;
let pendingAdminMenuAccessAction = null;
let pendingClientsAccessResolver = null;
let appConfirmResolver = null;
let pendingResetToken = '';
let pendingResetScope = '';
let pendingExportReasonLabel = '';
let pendingExportReasonValue = '';
let pendingExportRetry = null;
let exportFlowPending = false;
let exportFlowCanceled = false;
let exportHistory = getStorageJson('exportHistory', []);
let pendingTeamAccessTeam = '';
let adminFacilityDirectoryOpen = false;
let activeMenuPage = '';
let leadDraftRecoveredAt = '';
const menuPageHistory = [];
let remoteSyncTimer = null;
let remoteSyncReady = false;
let remoteSyncInFlight = false;
let adminLiveRefreshTimer = null;
let adminLiveRefreshInterval = null;
let lastActivePageId = 'landing-page';
let uiRevealObserver = null;
let dynamicUiObserver = null;
let uiRefreshTimer = null;
let authMode = 'signin';
let appUser = (sessionStorage.getItem(SESSION_KEYS.appUser) || '').trim();
let dashboardAutoRefreshTimer = null;
let cloudPresenceTimer = null;
let successModalPrimaryAction = null;
let settingsUserFilter = '';
let settingsAccessTarget = '';
let inactivityTimer = null;
let inactivityMinutes = Math.max(5, Number(localStorage.getItem(STORAGE_KEYS.inactivityMinutes) || 30));
let deferredInstallPromptEvent = null;
let uiPrefs = {
    compactUi: false,
    highContrastTables: true,
    reduceMotion: false
};
const USER_PERMISSION_KEYS = ['admin', 'learning', 'forms', 'leads', 'settings'];
const TERMS_POLICY_VERSION = '2026-02-13';
const ADMIN_LIVE_REFRESH_KEYS = new Set([
    STORAGE_KEYS.records,
    STORAGE_KEYS.leads,
    STORAGE_KEYS.interventions,
    STORAGE_KEYS.appointments,
    STORAGE_KEYS.userAccounts,
    STORAGE_KEYS.facilities,
    STORAGE_KEYS.archivedJfas,
    STORAGE_KEYS.auditLog
]);
let teamSettingsOpen = false;
const USER_PERMISSION_LABELS = {
    admin: 'Admin',
    learning: 'Learning',
    forms: 'Forms',
    leads: 'Leads',
    settings: 'Settings'
};

function applyOneTimeAdminDefaultBootstrap() {
    if (localStorage.getItem(ADMIN_DEFAULT_BOOTSTRAP_MARKER) === 'done') return;
    const accounts = getUserAccounts();
    const existing = accounts.admin || {};
    accounts.admin = {
        ...existing,
        username: DEFAULT_ADMIN_USERNAME,
        active: true,
        adminOnly: true,
        adminDefaultLocked: false,
        permissions: normalizeUserPermissions(existing.permissions, true),
        password: DEFAULT_ADMIN_PASSWORD,
        passwordHash: '',
        passwordSalt: '',
        updatedAt: new Date().toISOString()
    };
    saveUserAccounts(accounts);
    markUsernameAsUsed(DEFAULT_ADMIN_USERNAME);
    localStorage.removeItem(STORAGE_KEYS.adminPassword);
    localStorage.setItem(ADMIN_DEFAULT_BOOTSTRAP_MARKER, 'done');
}

function seedUsedLeadIdsFromCurrentRecords() {
    const merged = new Set(
        [
            ...usedLeadIds,
            ...leadRecords
                .map((lead) => String(lead?.leadId || '').trim().toUpperCase())
                .filter(Boolean)
        ]
    );
    if (merged.size !== usedLeadIds.size) {
        usedLeadIds = merged;
        scheduleStorageWrite(STORAGE_KEYS.usedLeadIds, JSON.stringify([...usedLeadIds]));
    }
}

seedUsedLeadIdsFromCurrentRecords();

function isJfaArchived(name) {
    const key = normalizeJfaName(name);
    return archivedJfaNames.has(key);
}

function archiveJfaName(name) {
    const key = normalizeJfaName(name);
    if (!key) return;
    archivedJfaNames.add(key);
    scheduleStorageWrite(STORAGE_KEYS.archivedJfas, JSON.stringify([...archivedJfaNames]));
}

function recordMatchesScope(record) {
    if (record?.name && isJfaArchived(record.name)) return false;
    if (adminRole === 'ADMIN') return true;
    if (adminRole === 'TEAM') {
        if (!adminTeam) return false;
        return record?.team === adminTeam;
    }
    if (adminRole === 'PERSONAL') {
        const identity = getLeadIdentity();
        if (!identity?.name) return false;
        if (identity.team && record?.team && record.team !== identity.team) return false;
        return normalizeJfaName(record?.name) === normalizeJfaName(identity.name);
    }
    return true;
}

function getScopedRecords() {
    return jfaRecords.filter(recordMatchesScope);
}

function setElementText(id, value) {
    const el = document.getElementById(id);
    if (!el) return false;
    el.textContent = String(value ?? '');
    return true;
}

function setInputValue(id, value) {
    const el = document.getElementById(id);
    if (!el) return false;
    el.value = String(value ?? '');
    return true;
}

function logAudit(action, details = '') {
    const log = JSON.parse(localStorage.getItem(STORAGE_KEYS.auditLog)) || [];
    log.unshift({
        time: new Date().toISOString(),
        action,
        details
    });
    scheduleStorageWrite(STORAGE_KEYS.auditLog, JSON.stringify(log.slice(0, 200)));
}

function scheduleStorageWrite(key, value) {
    if (storageWriteQueue.has(key)) {
        clearTimeout(storageWriteQueue.get(key));
    }
    setSyncState(navigator.onLine ? 'syncing' : 'offline');
    const handle = setTimeout(() => {
        localStorage.setItem(key, value);
        updateLastSaved();
        scheduleRemoteSync();
        if (ADMIN_LIVE_REFRESH_KEYS.has(key)) {
            requestAdminLiveRefresh();
        }
        storageWriteQueue.delete(key);
    }, CONFIG.DEBOUNCE_DELAY);
    storageWriteQueue.set(key, handle);
}

function isAdminLiveRefreshActive() {
    return adminRole === 'ADMIN' && isAdminStandaloneActive();
}

function updateAdminStandaloneHeroCounters() {
    if (!isAdminLiveRefreshActive()) return;
    const totalLeadsEl = document.getElementById('adminHeroTotalLeads');
    const pendingLeadsEl = document.getElementById('adminHeroPendingLeads');
    const jfasEl = document.getElementById('adminHeroJfas');
    const fasInRegisterEl = document.getElementById('adminHeroFasInRegister');
    const facilitiesEl = document.getElementById('adminHeroFacilities');
    const syncEl = document.getElementById('adminHeroLastSync');
    if (totalLeadsEl) totalLeadsEl.textContent = String(leadRecords.length);
    if (pendingLeadsEl) {
        const pending = leadRecords.filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Pending').length;
        pendingLeadsEl.textContent = String(pending);
    }
    if (jfasEl) jfasEl.textContent = String(getCompanyJfaDirectory().length);
    if (fasInRegisterEl) fasInRegisterEl.textContent = String(getTodayFaAttendanceRows().length);
    if (facilitiesEl) facilitiesEl.textContent = String(facilities.length);
    if (syncEl) syncEl.textContent = new Date().toLocaleString('en-ZA');
}

function requestAdminLiveRefresh() {
    if (!isAdminLiveRefreshActive()) return;
    if (adminLiveRefreshTimer) clearTimeout(adminLiveRefreshTimer);
    adminLiveRefreshTimer = setTimeout(() => {
        adminLiveRefreshTimer = null;
        if (!isAdminLiveRefreshActive()) return;
        updateAdminStandaloneHeroCounters();
        renderAdminStandaloneInsights();
    }, 120);
}

function startAdminLiveRefreshLoop() {
    if (adminLiveRefreshInterval) clearInterval(adminLiveRefreshInterval);
    adminLiveRefreshInterval = setInterval(() => {
        if (!isAdminLiveRefreshActive()) return;
        requestAdminLiveRefresh();
    }, 15000);
}

function debounce(fn, wait = 250) {
    let timer = null;
    return (...args) => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => fn(...args), wait);
    };
}

function syncMobileViewportHeight() {
    const height = Math.round(window.visualViewport?.height || window.innerHeight || 0);
    if (!height) return;
    document.documentElement.style.setProperty('--mobile-vh', `${height}px`);
}

const syncMobileViewportHeightDebounced = debounce(syncMobileViewportHeight, 120);

function bindMobileViewportHeightSync() {
    if (window.__matlaViewportSyncBound) return;
    window.__matlaViewportSyncBound = true;
    syncMobileViewportHeight();
    window.addEventListener('resize', syncMobileViewportHeightDebounced);
    window.addEventListener('orientationchange', syncMobileViewportHeightDebounced);
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', syncMobileViewportHeightDebounced);
    }
}

function buildRemoteStatePayload() {
    const payload = {};
    REMOTE_SYNC_KEYS.forEach((key) => {
        const value = localStorage.getItem(key);
        if (value !== null) payload[key] = value;
    });
    return payload;
}

function applyRemoteStatePayload(payload) {
    if (!payload || typeof payload !== 'object') return;
    REMOTE_SYNC_KEYS.forEach((key) => {
        if (Object.prototype.hasOwnProperty.call(payload, key)) {
            localStorage.setItem(key, String(payload[key]));
        }
    });
}

function localHasImportantState() {
    const records = JSON.parse(localStorage.getItem(STORAGE_KEYS.records) || '[]');
    const leads = JSON.parse(localStorage.getItem(STORAGE_KEYS.leads) || '[]');
    const customFacilities = JSON.parse(localStorage.getItem(STORAGE_KEYS.customFacilities) || '[]');
    return records.length > 0 || leads.length > 0 || customFacilities.length > 0;
}

async function pushStateToRemote() {
    if (!remoteSyncReady || remoteSyncInFlight || !isRemoteSyncAllowed()) return false;
    if (!(await refreshRemoteAccessTokenIfNeeded())) return false;
    remoteSyncInFlight = true;
    if (navigator.onLine) setSyncState('syncing');
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/save`, {
            method: 'POST',
            headers: buildRemoteHeaders(),
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                payload: buildRemoteStatePayload()
            })
        });
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) clearRemoteAuthState();
            throw new Error(`save failed: ${response.status}`);
        }
        const data = await response.json();
        if (data?.updatedAt) {
            localStorage.setItem(STORAGE_KEYS.remoteSyncAt, data.updatedAt);
        } else {
            localStorage.setItem(STORAGE_KEYS.remoteSyncAt, new Date().toISOString());
        }
        updateLastSaved();
        return true;
    } catch (_) {
        // Keep the app fully offline-capable when API is unavailable.
        if (!navigator.onLine) setSyncState('offline');
        else setSyncState('error');
        return false;
    } finally {
        remoteSyncInFlight = false;
    }
}

async function syncCriticalCloudState(label = 'Update') {
    if (!isCloudSyncRequired()) return true;
    const ok = await pushStateToRemote();
    if (!ok) {
        showToast(`${label} saved locally. Cloud sync pending; keep internet on.`, 'error');
    }
    return ok;
}

function scheduleRemoteSync() {
    if (!remoteSyncReady) return;
    if (remoteSyncTimer) clearTimeout(remoteSyncTimer);
    remoteSyncTimer = setTimeout(() => {
        pushStateToRemote();
    }, CONFIG.STORAGE_WRITE_DELAY * 6);
}

async function initializeRemotePersistence() {
    if (!isRemoteSyncAllowed()) {
        remoteSyncReady = false;
        return;
    }
    if (!(await refreshRemoteAccessTokenIfNeeded())) {
        remoteSyncReady = false;
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/load?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        if (!response.ok) throw new Error(`load failed: ${response.status}`);
        const data = await response.json();
        const remotePayload = data?.payload && typeof data.payload === 'object' ? data.payload : null;
        const remoteUpdatedAt = data?.updatedAt ? new Date(data.updatedAt).getTime() : 0;
        const localSyncedAt = localStorage.getItem(STORAGE_KEYS.remoteSyncAt);
        const localSyncedTime = localSyncedAt ? new Date(localSyncedAt).getTime() : 0;
        const hasLocal = localHasImportantState();
        const hasRemote = remotePayload && Object.keys(remotePayload).length > 0;

        if (hasRemote && (!hasLocal || remoteUpdatedAt > localSyncedTime)) {
            applyRemoteStatePayload(remotePayload);
            localStorage.setItem(STORAGE_KEYS.remoteSyncAt, data.updatedAt || new Date().toISOString());
        } else if (hasLocal && !hasRemote) {
            remoteSyncReady = true;
            await pushStateToRemote();
        }
        remoteSyncReady = true;
    } catch (_) {
        remoteSyncReady = false;
    }
}

function rebuildFacilityIndex() {
    facilitiesById = new Map(facilities.map((f) => [f.id, f]));
}

function sortFacilitiesAlphabetically() {
    facilities.sort((a, b) => {
        const aName = (a?.name || '').trim();
        const bName = (b?.name || '').trim();
        return aName.localeCompare(bName, 'en', { sensitivity: 'base' });
    });
    rebuildFacilityIndex();
}

function getFacilityById(id) {
    return facilitiesById.get(id) || facilities.find((f) => f.id === id);
}

function normalizeFacilityName(name) {
    return (name || '').toLowerCase().replace(/[^a-z0-9]+/g, '').trim();
}

function normalizeStrictFacilityKey(name) {
    return (name || '')
        .toLowerCase()
        .replace(/\b(memorial|hospital|prison)\b/g, '')
        .replace(/[^a-z0-9]+/g, '')
        .trim();
}

function expandFacilityName(name) {
    return (name || '').replace(/\bPS\b/gi, 'Police Station').trim();
}

function detectFacilityType(name) {
    const lower = (name || '').toLowerCase();
    if (lower.includes('court')) return 'Government';
    if (lower.includes('education')) return 'Government';
    if (lower.includes('home affairs')) return 'Government';
    if (lower.includes('stats sa')) return 'Government';
    if (lower.includes('development')) return 'Government';
    if (lower.includes('agriculture')) return 'Government';
    if (lower.includes('military')) return 'Government';
    if (lower.includes('saps')) return 'Police Station';
    if (lower.includes('police station')) return 'Police Station';
    if (lower === 'police station') return 'Police Station';
    if (lower.includes('clinic')) return 'Clinic';
    if (lower.includes('hospital')) return 'Hospital';
    if (lower.includes('prison')) return 'Prison';
    if (lower.includes('school')) return 'School';
    if (lower.includes('high')) return 'School';
    if (lower.includes('primary')) return 'School';
    if (lower.includes('secondary')) return 'School';
    if (lower.includes('sec')) return 'School';
    if (lower.includes('pschool') || lower.includes('p.school') || lower.includes(' p school')) return 'School';
    return 'Other';
}

function addUnrestrictedFacilities2026() {
    if (!Array.isArray(unrestrictedFacilities2026) || unrestrictedFacilities2026.length === 0) return;
    const existing = new Set(facilities.map((f) => normalizeFacilityName(f.name)));
    const ordered = [...unrestrictedFacilities2026]
        .filter(Boolean)
        .map((n) => n.trim())
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' }));
    let nextId = facilities.reduce((max, f) => Math.max(max, f.id), 0) + 1;
    ordered.forEach((raw) => {
        const name = expandFacilityName(raw);
        const normalized = normalizeFacilityName(name);
        if (!normalized || existing.has(normalized)) return;
        facilities.push({
            id: nextId++,
            name,
            type: detectFacilityType(name),
            area: 'Unspecified',
            contact: 'Receptionist',
            phone: 'Unavailable',
            allocations: 0,
            visits: [],
            consentForms: 0,
            hasDayRules: false
        });
        existing.add(normalized);
    });
    sortFacilitiesAlphabetically();
}

function parseAllowedDays(text, status = '') {
    const statusNorm = (status || '').toLowerCase();
    let raw = (text || '').toLowerCase().replace(/\s+/g, '');
    if (!raw || raw === 'pending') return [];
    if ((raw === 'active' || raw === 'inactive') && !statusNorm) {
        return [];
    }
    if (raw.includes('daily')) return [1, 2, 3, 4, 5];
    raw = raw.replace('tueday', 'tuesday');
    const tokens = raw.split(/[\/,]/).filter(Boolean);
    const map = {
        mon: 1,
        monday: 1,
        mondays: 1,
        tue: 2,
        tues: 2,
        tuesday: 2,
        tuesdays: 2,
        wed: 3,
        weds: 3,
        wednesday: 3,
        thur: 4,
        thurs: 4,
        thursday: 4,
        thu: 4,
        fri: 5,
        friday: 5
    };
    const days = tokens.map((t) => map[t]).filter((v) => Number.isFinite(v));
    return [...new Set(days)];
}

function isFacilityAvailableToday(facility, date = new Date()) {
    if (!facility) return false;
    const day = date.getDay();
    if (day === 0 || day === 6) return false;
    const hasDayRules = facility.hasDayRules === true;
    if (!hasDayRules) return true;
    if (facility.status && facility.status.toLowerCase() !== 'active') return false;
    const allowed = facility.allowedDays;
    if (!Array.isArray(allowed) || allowed.length === 0) return false;
    return allowed.includes(day);
}

function normalizeJfaName(name) {
    return (name || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function formatJfaName(name) {
    const cleaned = (name || '').trim().replace(/\s+/g, ' ');
    if (!cleaned) return '';
    return cleaned.replace(/\b\w/g, (m) => m.toUpperCase());
}

function formatAuthIdentifier(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (raw.includes('@')) return raw.toLowerCase();
    return formatJfaName(raw);
}

function resolveAccountKey(identifier) {
    const raw = String(identifier || '').trim();
    if (!raw) return '';
    const accounts = getUserAccounts();
    const key = normalizeJfaName(raw);
    if (accounts[key]) return key;
    const usernameEntry = Object.entries(accounts).find(([, account]) => normalizeJfaName(account?.username || '') === key);
    if (usernameEntry) return usernameEntry[0];
    if (raw.includes('@')) {
        const email = raw.toLowerCase();
        const profileEntry = Object.entries(jfaProfiles).find(([, profile]) => String(profile?.email || '').toLowerCase() === email);
        if (profileEntry) return profileEntry[0];
        const accountEntry = Object.entries(accounts).find(([, account]) => String(account?.email || '').toLowerCase() === email);
        if (accountEntry) return accountEntry[0];
    }
    return key;
}

function splitJfaName(fullName) {
    const clean = formatJfaName(fullName || '');
    if (!clean) return { name: '', surname: '' };
    const parts = clean.split(' ');
    const name = parts.shift() || '';
    return { name, surname: parts.join(' ') };
}

function ensureJfaProfile(fullName, seed = {}) {
    const key = normalizeJfaName(fullName);
    if (!key) return null;
    const split = splitJfaName(fullName);
    const existing = jfaProfiles[key] || {};
    const profile = {
        fullName: formatJfaName(existing.fullName || fullName),
        name: existing.name || split.name || '',
        surname: existing.surname || split.surname || '',
        phone: existing.phone || seed.phone || '',
        email: existing.email || '',
        address: existing.address || '',
        bankName: existing.bankName || '',
        accountNumber: existing.accountNumber || '',
        branchCode: existing.branchCode || '',
        taxNumber: existing.taxNumber || '',
        nextOfKinName: existing.nextOfKinName || '',
        nextOfKinPhone: existing.nextOfKinPhone || '',
        nextOfKinRelationship: existing.nextOfKinRelationship || '',
        team: existing.team || seed.team || ''
    };
    jfaProfiles[key] = profile;
    return profile;
}

function saveJfaProfiles() {
    scheduleStorageWrite(STORAGE_KEYS.jfaProfiles, JSON.stringify(jfaProfiles));
}

function ensureFaProfile(fullName, seed = {}) {
    const key = normalizeJfaName(fullName);
    if (!key) return null;
    const split = splitJfaName(fullName);
    const existing = faProfiles[key] || {};
    const profile = {
        key,
        fullName: formatJfaName(existing.fullName || fullName),
        name: existing.name || split.name || '',
        surname: existing.surname || split.surname || '',
        username: existing.username || seed.username || key,
        phone: existing.phone || seed.phone || '',
        email: existing.email || seed.email || '',
        address: existing.address || '',
        bankName: existing.bankName || '',
        accountNumber: existing.accountNumber || '',
        branchCode: existing.branchCode || '',
        taxNumber: existing.taxNumber || '',
        nextOfKinName: existing.nextOfKinName || '',
        nextOfKinPhone: existing.nextOfKinPhone || '',
        nextOfKinRelationship: existing.nextOfKinRelationship || '',
        team: existing.team || seed.team || '',
        status: existing.status || seed.status || 'Active',
        createdAt: existing.createdAt || seed.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    faProfiles[key] = profile;
    return profile;
}

function saveFaProfiles() {
    scheduleStorageWrite(STORAGE_KEYS.faProfiles, JSON.stringify(faProfiles));
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function isRemoteSyncAllowed() {
    try {
        const url = new URL(REMOTE_API_BASE, window.location.origin);
        const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
        const allowInsecureRemote = window.JFA_ALLOW_INSECURE_REMOTE === true;
        const isSameOriginHttp = url.origin === window.location.origin && window.location.protocol === 'http:';
        return url.protocol === 'https:' || isLocalhost || allowInsecureRemote || isSameOriginHttp;
    } catch (_) {
        return false;
    }
}

function isHostedEnvironment() {
    const host = String(window.location.hostname || '').toLowerCase();
    return Boolean(host && host !== 'localhost' && host !== '127.0.0.1');
}

function isCloudSyncRequired() {
    if (window.JFA_REQUIRE_REMOTE_SYNC === false) return false;
    return isHostedEnvironment() && navigator.onLine;
}

function getRemoteAuthState() {
    return {
        accessToken: (sessionStorage.getItem(SESSION_KEYS.remoteAccessToken) || '').trim(),
        refreshToken: (sessionStorage.getItem(SESSION_KEYS.remoteRefreshToken) || '').trim(),
        sessionId: (sessionStorage.getItem(SESSION_KEYS.remoteSessionId) || '').trim(),
        accessExpAt: Number(sessionStorage.getItem(SESSION_KEYS.remoteAccessExpAt) || 0),
        refreshExpAt: Number(sessionStorage.getItem(SESSION_KEYS.remoteRefreshExpAt) || 0)
    };
}

function setRemoteAuthState({ accessToken = '', refreshToken = '', sessionId = '', expiresIn = 0, refreshExpiresIn = 0 } = {}) {
    const now = Date.now();
    if (accessToken) sessionStorage.setItem(SESSION_KEYS.remoteAccessToken, accessToken);
    if (refreshToken) sessionStorage.setItem(SESSION_KEYS.remoteRefreshToken, refreshToken);
    if (sessionId) sessionStorage.setItem(SESSION_KEYS.remoteSessionId, sessionId);
    if (Number(expiresIn) > 0) {
        sessionStorage.setItem(SESSION_KEYS.remoteAccessExpAt, String(now + (Number(expiresIn) * 1000)));
    }
    if (Number(refreshExpiresIn) > 0) {
        sessionStorage.setItem(SESSION_KEYS.remoteRefreshExpAt, String(now + (Number(refreshExpiresIn) * 1000)));
    }
}

function clearRemoteAuthState() {
    sessionStorage.removeItem(SESSION_KEYS.remoteAccessToken);
    sessionStorage.removeItem(SESSION_KEYS.remoteRefreshToken);
    sessionStorage.removeItem(SESSION_KEYS.remoteSessionId);
    sessionStorage.removeItem(SESSION_KEYS.remoteAccessExpAt);
    sessionStorage.removeItem(SESSION_KEYS.remoteRefreshExpAt);
}

function isRemoteSignedSessionActive() {
    const state = getRemoteAuthState();
    return Boolean(state.accessToken && state.sessionId && state.accessExpAt > Date.now());
}

async function refreshRemoteAccessTokenIfNeeded(force = false) {
    if (!isRemoteSyncAllowed()) return false;
    const state = getRemoteAuthState();
    if (!state.refreshToken || !state.sessionId) return false;
    if (!force && state.accessToken && state.accessExpAt > (Date.now() + 60 * 1000)) return true;
    if (state.refreshExpAt && state.refreshExpAt <= Date.now()) {
        clearRemoteAuthState();
        return false;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(REMOTE_API_TOKEN ? { Authorization: `Bearer ${REMOTE_API_TOKEN}` } : {})
            },
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                sessionId: state.sessionId,
                refreshToken: state.refreshToken
            })
        });
        if (!response.ok) {
            clearRemoteAuthState();
            return false;
        }
        const data = await response.json().catch(() => ({}));
        setRemoteAuthState({
            accessToken: data?.accessToken || '',
            refreshToken: data?.refreshToken || '',
            sessionId: data?.sessionId || state.sessionId,
            expiresIn: Number(data?.expiresIn || 0),
            refreshExpiresIn: Number(data?.refreshExpiresIn || 0)
        });
        return true;
    } catch (_) {
        return false;
    }
}

function buildRemoteHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const state = getRemoteAuthState();
    if (state.accessToken) {
        headers.Authorization = `Bearer ${state.accessToken}`;
    } else if (REMOTE_API_TOKEN) {
        headers.Authorization = `Bearer ${REMOTE_API_TOKEN}`;
    }
    return headers;
}

function getUserAccounts() {
    const raw = getStorageJson(STORAGE_KEYS.userAccounts, {});
    return raw && typeof raw === 'object' ? raw : {};
}

function isCryptoAvailable() {
    return Boolean(window.crypto && crypto.subtle && typeof TextEncoder !== 'undefined');
}

function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach((b) => {
        binary += String.fromCharCode(b);
    });
    return btoa(binary);
}

function generateSalt() {
    if (!window.crypto || !crypto.getRandomValues) {
        return String(Date.now());
    }
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bufferToBase64(bytes);
}

async function hashPasswordWithSalt(password, salt) {
    const input = `${salt}:${String(password || '')}`;
    if (!isCryptoAvailable()) {
        return btoa(input);
    }
    const data = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return bufferToBase64(digest);
}

async function createPasswordRecord(password) {
    const salt = generateSalt();
    const hash = await hashPasswordWithSalt(password, salt);
    return { salt, hash, algo: 'sha256' };
}

async function verifyPasswordRecord(password, record) {
    if (!record || !record.salt || !record.hash) return false;
    const hash = await hashPasswordWithSalt(password, record.salt);
    return hash === record.hash;
}

const PASSWORD_POLICY = {
    minLength: 8,
    requireUpper: true,
    requireLower: true,
    requireNumber: true,
    requireSpecial: true
};

function validateStrongPassword(passwordRaw) {
    const password = String(passwordRaw || '');
    if (password.length < PASSWORD_POLICY.minLength) {
        return {
            ok: false,
            message: 'Password must be at least 8 characters long.'
        };
    }
    if (PASSWORD_POLICY.requireUpper && !/[A-Z]/.test(password)) {
        return {
            ok: false,
            message: 'Password must include at least 1 uppercase letter.'
        };
    }
    if (PASSWORD_POLICY.requireLower && !/[a-z]/.test(password)) {
        return {
            ok: false,
            message: 'Password must include at least 1 lowercase letter.'
        };
    }
    if (PASSWORD_POLICY.requireNumber && !/[0-9]/.test(password)) {
        return {
            ok: false,
            message: 'Password must include at least 1 number.'
        };
    }
    if (PASSWORD_POLICY.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
        return {
            ok: false,
            message: 'Password must include at least 1 special character.'
        };
    }
    return { ok: true, message: '' };
}

function getPasswordStrengthSnapshot(passwordRaw) {
    const password = String(passwordRaw || '');
    const checks = {
        length8: password.length >= 8,
        length12: password.length >= 12,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[^A-Za-z0-9]/.test(password)
    };
    const score = Object.values(checks).filter(Boolean).length;
    if (!password) {
        return { score: 0, width: 0, label: 'Password strength: —', tone: '' };
    }
    if (score <= 2) {
        return { score, width: 25, label: 'Password strength: Weak', tone: 'weak' };
    }
    if (score <= 4) {
        return { score, width: 50, label: 'Password strength: Fair', tone: 'fair' };
    }
    if (score === 5) {
        return { score, width: 75, label: 'Password strength: Good', tone: 'good' };
    }
    return { score, width: 100, label: 'Password strength: Strong', tone: 'strong' };
}

function ensurePasswordStrengthMarkup(container) {
    if (!container) return null;
    if (!container.querySelector('.password-strength-track')) {
        container.innerHTML = `
            <div class="password-strength-track">
                <div class="password-strength-fill"></div>
            </div>
            <div class="password-strength-label">Password strength: —</div>
        `;
    }
    return {
        fill: container.querySelector('.password-strength-fill'),
        label: container.querySelector('.password-strength-label')
    };
}

function updatePasswordStrengthForInput(inputEl, meterEl) {
    if (!inputEl || !meterEl) return;
    const parts = ensurePasswordStrengthMarkup(meterEl);
    if (!parts?.fill || !parts?.label) return;
    const snapshot = getPasswordStrengthSnapshot(inputEl.value || '');
    parts.fill.style.width = `${snapshot.width}%`;
    parts.fill.classList.remove('weak', 'fair', 'good', 'strong');
    if (snapshot.tone) parts.fill.classList.add(snapshot.tone);
    parts.label.textContent = snapshot.label;
}

function bindPasswordStrengthIndicators(root = document) {
    const bindings = [
        { inputId: 'authPassword', meterId: 'authPasswordStrength' },
        { inputId: 'settingsNewPassword', meterId: 'settingsNewPasswordStrength' },
        { inputId: 'settingsUserPassword', meterId: 'settingsUserPasswordStrength' },
        { inputId: 'settingsAdminPassword', meterId: 'settingsAdminPasswordStrength' },
        { inputId: 'masterLeaderPassword', meterId: 'masterLeaderPasswordStrength' }
    ];
    bindings.forEach(({ inputId, meterId }) => {
        const inputEl = root.getElementById ? root.getElementById(inputId) : document.getElementById(inputId);
        const meterEl = root.getElementById ? root.getElementById(meterId) : document.getElementById(meterId);
        if (!inputEl || !meterEl) return;
        if (inputEl.dataset.strengthBound !== '1') {
            inputEl.addEventListener('input', () => updatePasswordStrengthForInput(inputEl, meterEl));
            inputEl.dataset.strengthBound = '1';
        }
        updatePasswordStrengthForInput(inputEl, meterEl);
    });
}

function getDefaultPermissions(isAdminUser = false) {
    if (isAdminUser) {
        return { admin: true, learning: true, forms: true, leads: true, settings: true };
    }
    return { admin: false, learning: true, forms: true, leads: true, settings: true };
}

function normalizeUserPermissions(permissions, isAdminUser = false) {
    const defaults = getDefaultPermissions(isAdminUser);
    const source = permissions && typeof permissions === 'object' ? permissions : {};
    const normalized = {};
    USER_PERMISSION_KEYS.forEach((key) => {
        normalized[key] = source[key] == null ? defaults[key] : Boolean(source[key]);
    });
    if (isAdminUser) normalized.admin = true;
    normalized.settings = true;
    return normalized;
}

function getCurrentUserPermissions() {
    const key = resolveAccountKey(appUser || '');
    if (!key) return normalizeUserPermissions({}, false);
    const accounts = getUserAccounts();
    const account = accounts[key];
    const isAdminUser = key === 'admin';
    return normalizeUserPermissions(account?.permissions, isAdminUser);
}

function hasAppPermission(permissionKey) {
    if (!appUser) return false;
    const perms = getCurrentUserPermissions();
    return perms[permissionKey] !== false;
}

function isTeamLeaderName(name, team = '') {
    const key = normalizeJfaName(name);
    if (!key || key === 'admin') return false;
    if (CORE_TEAM_LEADER_KEYS.has(key)) return true;
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account || account.active === false || account.adminOnly === true) return false;
    const perms = normalizeUserPermissions(account.permissions, false);
    if (perms.admin !== true) return false;
    if (!team) return true;
    return normalizeJfaName(account.team || '') === normalizeJfaName(team);
}

function canAccessMenuPage(page) {
    const map = {
        admin: 'admin',
        teamDetail: 'admin',
        archivedJfas: 'admin',
        learning: 'learning',
        learningDetail: 'learning',
        forms: 'forms',
        leads: 'leads',
        payments: 'leads',
        benSystem: 'leads',
        appointments: 'leads',
        settings: 'settings'
    };
    const permKey = map[page];
    if (!permKey) return true;
    return hasAppPermission(permKey);
}

function ensureDefaultUserAccount() {
    const accounts = getUserAccounts();
    const existing = accounts.admin || {};
    const lockDefaultCredentials = existing.adminDefaultLocked === true;
    const needsPassword = !(existing.passwordHash && existing.passwordSalt);
    const defaultUsername = lockDefaultCredentials
        ? formatAuthIdentifier(existing.username || DEFAULT_ADMIN_USERNAME) || DEFAULT_ADMIN_USERNAME
        : DEFAULT_ADMIN_USERNAME;
    accounts.admin = {
        username: defaultUsername,
        createdAt: existing.createdAt || new Date().toISOString(),
        lastLoginAt: existing.lastLoginAt || '',
        active: true,
        adminOnly: true,
        adminDefaultLocked: lockDefaultCredentials,
        permissions: normalizeUserPermissions(existing.permissions, true),
        passwordHash: existing.passwordHash || '',
        passwordSalt: existing.passwordSalt || '',
        password: lockDefaultCredentials ? '' : DEFAULT_ADMIN_PASSWORD,
        updatedAt: new Date().toISOString()
    };
    if (lockDefaultCredentials) delete accounts.admin.password;
    saveUserAccounts(accounts);
    markUsernameAsUsed('admin');
    // Keep default admin/admin credentials until admin explicitly changes password once.
    if (needsPassword || !lockDefaultCredentials) {
        createPasswordRecord(DEFAULT_ADMIN_PASSWORD).then((record) => {
            const refreshed = getUserAccounts();
            const admin = refreshed.admin;
            if (!admin) return;
            if (admin.adminDefaultLocked === true) return;
            admin.passwordHash = record.hash;
            admin.passwordSalt = record.salt;
            admin.adminDefaultLocked = lockDefaultCredentials;
            admin.username = DEFAULT_ADMIN_USERNAME;
            admin.password = DEFAULT_ADMIN_PASSWORD;
            refreshed.admin = admin;
            saveUserAccounts(refreshed);
        });
    }
}

function ensureDefaultTeamLeaderAccounts() {
    const accounts = getUserAccounts();
    let changed = false;
    CORE_TEAM_LEADER_SEEDS.forEach((seed) => {
        const username = formatJfaName(seed.username || '');
        const key = normalizeJfaName(username);
        if (!key || key === 'admin') return;
        const hadExisting = Boolean(accounts[key]);
        const existing = accounts[key] || {};
        accounts[key] = {
            username,
            email: String(existing.email || seed.email || '').toLowerCase(),
            team: String(existing.team || seed.team || '').trim(),
            password: existing.password || seed.password || 'Temp@123!',
            passwordHash: existing.passwordHash,
            passwordSalt: existing.passwordSalt,
            createdAt: existing.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            active: existing.active !== false,
            permissions: normalizeUserPermissions({ ...(existing.permissions || {}), admin: true, settings: true }, false)
        };
        if (!hadExisting || normalizeUserPermissions(existing.permissions, false).admin !== true || !existing.team || !existing.email) {
            changed = true;
        }
        markUsernameAsUsed(username);
        const profile = ensureJfaProfile(username, { team: accounts[key].team }) || {};
        profile.team = accounts[key].team;
        profile.email = accounts[key].email || profile.email || '';
        jfaProfiles[key] = profile;
    });
    if (changed) {
        saveUserAccounts(accounts);
        saveJfaProfiles();
    }
}

function saveUserAccounts(accounts) {
    scheduleStorageWrite(STORAGE_KEYS.userAccounts, JSON.stringify(accounts || {}));
}

function getUsedUsernameRegistry() {
    try {
        const raw = JSON.parse(localStorage.getItem(STORAGE_KEYS.usedUsernames) || '[]');
        return new Set(Array.isArray(raw) ? raw.map((item) => normalizeJfaName(item)).filter(Boolean) : []);
    } catch (_) {
        return new Set();
    }
}

function saveUsedUsernameRegistry(set) {
    const values = [...(set || new Set())].filter(Boolean);
    scheduleStorageWrite(STORAGE_KEYS.usedUsernames, JSON.stringify(values));
}

function markUsernameAsUsed(usernameRaw) {
    const key = normalizeJfaName(usernameRaw || '');
    if (!key) return;
    const set = getUsedUsernameRegistry();
    if (set.has(key)) return;
    set.add(key);
    saveUsedUsernameRegistry(set);
}

function hydrateUsedUsernameRegistry() {
    const set = getUsedUsernameRegistry();
    const accounts = getUserAccounts();
    Object.keys(accounts).forEach((key) => set.add(normalizeJfaName(key)));
    saveUsedUsernameRegistry(set);
}

function isUsernameUnavailable(usernameRaw, accounts = null) {
    const key = normalizeJfaName(usernameRaw || '');
    if (!key) return false;
    const sourceAccounts = accounts || getUserAccounts();
    if (sourceAccounts[key]) return true;
    const set = getUsedUsernameRegistry();
    return set.has(key);
}

async function verifyAndMigrateAccountPassword(account, inputPassword, accounts, key) {
    if (!account) return false;
    const password = String(inputPassword || '');
    if (account.passwordHash && account.passwordSalt) {
        return verifyPasswordRecord(password, { salt: account.passwordSalt, hash: account.passwordHash });
    }
    if (String(account.password || '') === password) {
        const record = await createPasswordRecord(password);
        account.passwordHash = record.hash;
        account.passwordSalt = record.salt;
        delete account.password;
        if (accounts && key) {
            accounts[key] = account;
            saveUserAccounts(accounts);
        }
        return true;
    }
    return false;
}

function setAuthUiError(message = '') {
    const el = document.getElementById('appAuthError');
    if (!el) return;
    el.textContent = message;
    el.style.display = message ? 'block' : 'none';
}

function setAuthCapsWarning(show) {
    const el = document.getElementById('authCapsWarning');
    if (!el) return;
    el.style.display = show ? 'block' : 'none';
}

function initGlobalErrorGuards() {
    window.addEventListener('error', (event) => {
        const message = String(event?.message || 'Unexpected app error.');
        console.error('Global error:', event?.error || message);
        showToast('Something went wrong. Please refresh and try again.', 'error');
        logAudit('Client error', message.slice(0, 180));
    });
    window.addEventListener('unhandledrejection', (event) => {
        const reason = event?.reason;
        const message = typeof reason === 'string'
            ? reason
            : String(reason?.message || 'Unhandled async error.');
        console.error('Unhandled rejection:', reason || message);
        showToast('A background task failed. Please retry.', 'error');
        logAudit('Unhandled rejection', message.slice(0, 180));
    });
}

function isAuthRememberEnabled() {
    return localStorage.getItem(STORAGE_KEYS.authRememberMe) === 'true';
}

function getRememberedAuthMode() {
    if (!isAuthRememberEnabled()) return 'signin';
    const saved = String(localStorage.getItem(STORAGE_KEYS.authRememberMode) || '').trim();
    if (saved === 'signup' || saved === 'admin' || saved === 'signin') return saved;
    return 'signin';
}

function persistAuthRememberState() {
    const rememberEl = document.getElementById('authRememberMe');
    const userEl = document.getElementById('authUsername');
    const shouldRemember = Boolean(rememberEl?.checked);
    scheduleStorageWrite(STORAGE_KEYS.authRememberMe, shouldRemember ? 'true' : 'false');
    if (!shouldRemember) {
        localStorage.removeItem(STORAGE_KEYS.authRememberMode);
        localStorage.removeItem(STORAGE_KEYS.authRememberUser);
        return;
    }
    if (authMode) scheduleStorageWrite(STORAGE_KEYS.authRememberMode, String(authMode));
    if (userEl?.value?.trim()) scheduleStorageWrite(STORAGE_KEYS.authRememberUser, userEl.value.trim());
}

function initAuthGateBindings() {
    const userEl = document.getElementById('authUsername');
    const passEl = document.getElementById('authPassword');
    const confirmEl = document.getElementById('authConfirmPassword');
    const showBtn = document.getElementById('authShowPasswordBtn');
    const rememberEl = document.getElementById('authRememberMe');
    if (rememberEl) {
        rememberEl.checked = isAuthRememberEnabled();
    }
    if (userEl) {
        const remembered = localStorage.getItem(STORAGE_KEYS.authRememberUser) || '';
        const saved = remembered || localStorage.getItem('lastAuthUser') || '';
        if (!userEl.value && saved) userEl.value = saved;
        userEl.addEventListener('change', () => {
            localStorage.setItem('lastAuthUser', userEl.value || '');
            if (rememberEl?.checked) scheduleStorageWrite(STORAGE_KEYS.authRememberUser, userEl.value || '');
        });
    }
    if (rememberEl) {
        rememberEl.addEventListener('change', () => {
            persistAuthRememberState();
        });
    }
    const handleCaps = (e) => {
        const on = e.getModifierState && e.getModifierState('CapsLock');
        setAuthCapsWarning(Boolean(on));
    };
    if (passEl) {
        passEl.addEventListener('keyup', handleCaps);
        passEl.addEventListener('keydown', handleCaps);
    }
    if (confirmEl) {
        confirmEl.addEventListener('keyup', handleCaps);
        confirmEl.addEventListener('keydown', handleCaps);
    }
    if (showBtn) {
        showBtn.addEventListener('click', () => {
            const next = showBtn.getAttribute('aria-pressed') !== 'true';
            showBtn.setAttribute('aria-pressed', next ? 'true' : 'false');
            showBtn.textContent = next ? 'Hide Password' : 'Show Password';
            const type = next ? 'text' : 'password';
            if (passEl) passEl.type = type;
            if (confirmEl) confirmEl.type = type;
        });
    }
    bindPasswordStrengthIndicators(document);
}

function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('service-worker.js?v=157').then((registration) => {
            registration.update().catch(() => {});
            if (registration.waiting) {
                registration.waiting.postMessage({ type: 'SKIP_WAITING' });
            }
            registration.addEventListener('updatefound', () => {
                const worker = registration.installing;
                if (!worker) return;
                worker.addEventListener('statechange', () => {
                    if (worker.state !== 'installed') return;
                    if (navigator.serviceWorker.controller) {
                        worker.postMessage({ type: 'SKIP_WAITING' });
                    }
                });
            });
        }).catch(() => {
            // ignore registration errors
        });
        navigator.serviceWorker.addEventListener('controllerchange', () => {
            if (window.__swReloading) return;
            window.__swReloading = true;
            window.location.reload();
        });
    });
}

function syncVisibleBuildVersion() {
    const siteVersion = document.getElementById('siteVersion');
    const adminSiteVersion = document.getElementById('adminSiteVersion');
    if (siteVersion) siteVersion.textContent = `v${APP_BUILD}`;
    if (adminSiteVersion) adminSiteVersion.textContent = `v${APP_BUILD}`;
}

async function enforceBuildRefresh() {
    const buildKey = STORAGE_KEYS.appBuild || 'appBuild';
    const previous = localStorage.getItem(buildKey) || '';
    if (previous === APP_BUILD) return;
    localStorage.setItem(buildKey, APP_BUILD);
    if ('caches' in window) {
        try {
            const keys = await caches.keys();
            await Promise.all(keys.filter((key) => key.startsWith('matla-jfa-')).map((key) => caches.delete(key)));
        } catch (_) {
            // ignore cache cleanup failures
        }
    }
    if ('serviceWorker' in navigator && navigator.serviceWorker.getRegistrations) {
        try {
            const regs = await navigator.serviceWorker.getRegistrations();
            await Promise.all(regs.map((reg) => reg.update().catch(() => {})));
            regs.forEach((reg) => {
                if (reg.waiting) reg.waiting.postMessage({ type: 'SKIP_WAITING' });
            });
        } catch (_) {
            // ignore sw refresh failures
        }
    }
    setTimeout(() => {
        if (window.__buildRefreshReloaded) return;
        window.__buildRefreshReloaded = true;
        window.location.reload();
    }, 120);
}

function updateAppUserBadge() {
    const badge = document.getElementById('appUserBadge');
    const btn = document.getElementById('switchUserBtn');
    const show = Boolean(appUser);
    const role = adminRole === 'ADMIN' ? 'ADMIN' : adminRole === 'TEAM' ? 'TEAM' : 'USER';
    if (badge) {
        badge.style.display = show ? 'inline-flex' : 'none';
        badge.textContent = show ? `User: ${formatJfaName(appUser)}` : 'User: —';
        badge.setAttribute('data-role', role);
        badge.title = show ? `Role: ${role}` : '';
    }
    if (btn) {
        btn.style.display = show ? 'inline-flex' : 'none';
    }
}

async function forceOneTimeCachePurgeOnLoad() {
    const doneKey = 'forceCachePurgeToken';
    const alreadyDone = localStorage.getItem(doneKey) || '';
    if (alreadyDone === FORCE_CACHE_PURGE_TOKEN) return;

    localStorage.setItem(doneKey, FORCE_CACHE_PURGE_TOKEN);

    if ('serviceWorker' in navigator && navigator.serviceWorker.getRegistrations) {
        try {
            const regs = await navigator.serviceWorker.getRegistrations();
            await Promise.all(regs.map((reg) => reg.unregister().catch(() => false)));
        } catch (_) {
            // ignore
        }
    }

    if ('caches' in window) {
        try {
            const keys = await caches.keys();
            await Promise.all(keys.map((key) => caches.delete(key).catch(() => false)));
        } catch (_) {
            // ignore
        }
    }

    if (!window.__forcedCachePurgeReloaded) {
        window.__forcedCachePurgeReloaded = true;
        setTimeout(() => window.location.reload(), 80);
    }
}

function setAuthMode(mode = 'signin') {
    authMode = mode === 'signup' ? 'signup' : mode === 'admin' ? 'admin' : 'signin';
    const signInBtn = document.getElementById('authSignInBtn');
    const createBtn = document.getElementById('authCreateBtn');
    const adminBtn = document.getElementById('authAdminBtn');
    const confirmGroup = document.getElementById('authConfirmGroup');
    const termsGroup = document.getElementById('authTermsGroup');
    const emailGroup = document.getElementById('authEmailGroup');
    const approvalNote = document.getElementById('authApprovalNote');
    const submitBtn = document.getElementById('authSubmitBtn');
    const modeHint = document.getElementById('authModeHint');
    if (signInBtn) signInBtn.classList.toggle('secondary', authMode !== 'signin');
    if (createBtn) createBtn.classList.toggle('secondary', authMode !== 'signup');
    if (adminBtn) adminBtn.classList.toggle('secondary', authMode !== 'admin');
    if (confirmGroup) confirmGroup.style.display = authMode === 'signup' ? 'block' : 'none';
    if (termsGroup) termsGroup.style.display = authMode === 'signup' ? 'block' : 'none';
    if (emailGroup) emailGroup.style.display = authMode === 'signup' ? 'block' : 'none';
    if (approvalNote) approvalNote.style.display = authMode === 'signup' ? 'block' : 'none';
    if (submitBtn) {
        if (authMode === 'signup') submitBtn.textContent = 'Create Account';
        else if (authMode === 'admin') submitBtn.textContent = 'Enter Admin Page';
        else submitBtn.textContent = 'Enter Dashboard';
    }
    if (modeHint) {
        if (authMode === 'admin') {
            modeHint.textContent = 'Enter admin credentials to continue.';
        } else if (authMode === 'signup') {
            modeHint.textContent = 'Create a new user account. Password must be 8+ chars with uppercase, lowercase, number, and special character.';
        } else {
            modeHint.textContent = 'Secure login before entering the dashboard. Use your own account details.';
        }
    }
    setAuthUiError('');
    persistAuthRememberState();
    bindPasswordStrengthIndicators(document);
}

function isAppUserAdmin() {
    const key = resolveAccountKey(appUser || '');
    if (!key) return false;
    if (key === 'admin') return true;
    const account = getUserAccounts()[key];
    return Boolean(account && account.adminOnly === true && account.active !== false);
}

function hasMasterAdminAccess() {
    const key = resolveAccountKey(appUser || '');
    if (!key) return false;
    if (adminRole === 'ADMIN' || key === 'admin') return true;
    const accounts = getUserAccounts();
    const account = accounts[key];
    return Boolean(account && account.adminOnly === true && account.active !== false);
}

function hasAdminUserSettingsAccess() {
    return hasMasterAdminAccess();
}

function getUserMgmtAuditLog() {
    const items = JSON.parse(localStorage.getItem(STORAGE_KEYS.userMgmtAudit) || '[]');
    return Array.isArray(items) ? items : [];
}

function logUserMgmtAction(action, detail = '') {
    const items = getUserMgmtAuditLog();
    items.unshift({
        timestamp: new Date().toISOString(),
        action,
        detail,
        by: formatJfaName(appUser || 'system')
    });
    scheduleStorageWrite(STORAGE_KEYS.userMgmtAudit, JSON.stringify(items.slice(0, 200)));
}

function loadUiPrefs() {
    try {
        const saved = JSON.parse(localStorage.getItem(STORAGE_KEYS.uiPrefs) || '{}');
        if (saved && typeof saved === 'object') {
            uiPrefs = {
                compactUi: Boolean(saved.compactUi),
                highContrastTables: saved.highContrastTables !== false,
                reduceMotion: Boolean(saved.reduceMotion)
            };
        }
    } catch (_) {
        // ignore corrupted UI prefs and fallback to defaults
    }
}

function applyUiPreferences() {
    document.body.classList.toggle('compact-ui', Boolean(uiPrefs.compactUi));
    document.body.classList.toggle('high-contrast-tables', Boolean(uiPrefs.highContrastTables));
    document.body.classList.toggle('reduce-motion', Boolean(uiPrefs.reduceMotion));
}

function saveUiPreferencesFromSettings() {
    const compact = document.getElementById('settingsCompactUi');
    const contrast = document.getElementById('settingsHighContrastTables');
    const reduceMotion = document.getElementById('settingsReduceMotion');
    uiPrefs = {
        compactUi: Boolean(compact?.checked),
        highContrastTables: Boolean(contrast?.checked),
        reduceMotion: Boolean(reduceMotion?.checked)
    };
    scheduleStorageWrite(STORAGE_KEYS.uiPrefs, JSON.stringify(uiPrefs));
    applyUiPreferences();
    showToast('Interface preferences saved.', 'success');
}

function saveInactivitySetting() {
    const input = document.getElementById('settingsInactivityMinutes');
    const value = Math.max(5, Math.min(240, Number(input?.value || inactivityMinutes || 30)));
    inactivityMinutes = Number.isFinite(value) ? value : 30;
    if (input) input.value = String(inactivityMinutes);
    scheduleStorageWrite(STORAGE_KEYS.inactivityMinutes, String(inactivityMinutes));
    resetInactivityTimer();
    showToast(`Auto-lock set to ${inactivityMinutes} minutes.`, 'success');
}

function forceSessionLockDueToInactivity() {
    if (!appUser || document.body.classList.contains('app-locked')) return;
    appUser = '';
    sessionStorage.removeItem(SESSION_KEYS.appUser);
    updateAppUserBadge();
    lockAppToAuth();
    setAuthMode(getRememberedAuthMode());
    showToast('Session locked due to inactivity.', 'error');
}

function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    if (!appUser || document.body.classList.contains('app-locked')) return;
    const ms = Math.max(5, inactivityMinutes) * 60 * 1000;
    inactivityTimer = setTimeout(forceSessionLockDueToInactivity, ms);
}

function bindInactivityWatchers() {
    const activityEvents = ['pointerdown', 'keydown', 'mousemove', 'touchstart', 'scroll'];
    activityEvents.forEach((evt) => {
        window.addEventListener(evt, resetInactivityTimer, { passive: true });
    });
    resetInactivityTimer();
}

function openShortcutsModal() {
    const modal = document.getElementById('shortcuts-modal');
    if (!modal) return;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeShortcutsModal() {
    const modal = document.getElementById('shortcuts-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function openSettingsPasswordAssist() {
    if (activeMenuPage !== 'settings') {
        openMenuPage('settings');
    }
    setTimeout(() => {
        const panel = document.getElementById('settingsPasswordAssistCard');
        const currentEl = document.getElementById('settingsCurrentPassword');
        const newEl = document.getElementById('settingsNewPassword');
        if (!panel || !currentEl || !newEl) {
            showToast('Password fields are not available right now.', 'error');
            return;
        }
        panel.style.display = '';
        panel.setAttribute('aria-hidden', 'false');
        panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
        currentEl.focus();
    }, 40);
}

function openSettingsAdminAccountCreator() {
    if (activeMenuPage !== 'settings') {
        openMenuPage('settings');
    }
    setTimeout(() => {
        const card = document.getElementById('settingsAdminAccountsCard');
        const usernameEl = document.getElementById('settingsAdminUsername');
        if (!card || !usernameEl) {
            showToast('Admin account creator is not available right now.', 'error');
            return;
        }
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        usernameEl.focus();
    }, 60);
}

function closeSettingsPasswordAssist(clearFields = true) {
    const panel = document.getElementById('settingsPasswordAssistCard');
    if (!panel) return;
    panel.style.display = 'none';
    panel.setAttribute('aria-hidden', 'true');
    if (!clearFields) return;
    const currentEl = document.getElementById('settingsCurrentPassword');
    const nextEl = document.getElementById('settingsNewPassword');
    const confirmEl = document.getElementById('settingsConfirmPassword');
    if (currentEl) currentEl.value = '';
    if (nextEl) nextEl.value = '';
    if (confirmEl) confirmEl.value = '';
    setSettingsError('settingsAccountError', '');
}

function renderSettingsPage() {
    const container = document.getElementById('settingsBody');
    if (!container) return;
    settingsAccessTarget = '';
    const adminControls = hasMasterAdminAccess();
    const adminUserControls = hasAdminUserSettingsAccess();
    const showEncryptedBackup = adminControls && adminRole === 'ADMIN';
    const teamAssignmentOptions = Object.values(getUserAccounts() || {})
        .filter((account) => account && typeof account === 'object')
        .map((account) => {
            const username = String(account.username || '').trim();
            const label = formatJfaName(username || 'Unknown User');
            return `<option value="${escapeHtml(username)}">${escapeHtml(label)}</option>`;
        })
        .join('') || '<option value="">No users available</option>';
    try {
        container.innerHTML = `
        <div class="insight-card" id="teamLeaderAccountCard">
            <h4>Account Security</h4>
            <p class="page-subtitle">Logged in as <strong>${escapeHtml(formatJfaName(appUser || 'Guest'))}</strong>.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsCurrentUsername">Current Username</label>
                    <input type="text" id="settingsCurrentUsername" value="${escapeHtml(formatJfaName(appUser || ''))}" readonly>
                </div>
                <div class="form-group">
                    <label for="settingsNewUsernameSelf">New Username</label>
                    <input type="text" id="settingsNewUsernameSelf" autocomplete="username" placeholder="Enter new username">
                </div>
                <div class="form-group">
                    <label for="settingsUsernamePassword">Current Password (for username change)</label>
                    <input type="password" id="settingsUsernamePassword" autocomplete="current-password">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="submitSettingsUsernameChange()">Change My Username</button>
                <button class="action-btn" type="button" onclick="openSettingsPasswordAssist()">Change My Password</button>
                ${adminUserControls ? `<button class="action-btn secondary" type="button" onclick="openSettingsAdminAccountCreator()">Create Admin User Account</button>` : ''}
                <button class="action-btn secondary" type="button" onclick="logoutAppUser()">Switch User</button>
            </div>
            <div class="insight-card" id="settingsPasswordAssistCard" style="display:none; margin-top:12px;" aria-hidden="true">
                <h4>Change Password</h4>
                <div class="master-capture-grid">
                    <div class="form-group">
                        <label for="settingsCurrentPassword">Current Password</label>
                        <input type="password" id="settingsCurrentPassword" autocomplete="current-password">
                    </div>
                    <div class="form-group">
                        <label for="settingsNewPassword">New Password</label>
                        <input type="password" id="settingsNewPassword" autocomplete="new-password">
                        <div id="settingsNewPasswordStrength" class="password-strength" aria-live="polite"></div>
                    </div>
                    <div class="form-group">
                        <label for="settingsConfirmPassword">Confirm New Password</label>
                        <input type="password" id="settingsConfirmPassword" autocomplete="new-password">
                    </div>
                </div>
                <div class="menu-page-actions">
                    <button class="action-btn" type="button" onclick="submitSettingsPasswordChange()">Update Password</button>
                    <button class="action-btn secondary" type="button" onclick="closeSettingsPasswordAssist()">Cancel</button>
                </div>
            </div>
            <div id="settingsAccountError" class="modal-error" style="display:none;"></div>
        </div>
        <div class="insight-card">
            <h4>Password</h4>
            <p class="page-subtitle">Quick option for user password updates.</p>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="openSettingsPasswordAssist()">Change My Password</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>Experience & Security</h4>
            <p class="page-subtitle">Tune visual comfort, performance, and auto-lock behavior.</p>
            <div class="master-capture-grid">
                <label class="radio-option">
                    <input type="checkbox" id="settingsCompactUi" ${uiPrefs.compactUi ? 'checked' : ''}>
                    <span class="radio-label">Compact UI spacing</span>
                </label>
                <label class="radio-option">
                    <input type="checkbox" id="settingsHighContrastTables" ${uiPrefs.highContrastTables ? 'checked' : ''}>
                    <span class="radio-label">High-contrast tables</span>
                </label>
                <label class="radio-option">
                    <input type="checkbox" id="settingsReduceMotion" ${uiPrefs.reduceMotion ? 'checked' : ''}>
                    <span class="radio-label">Reduce motion effects</span>
                </label>
                <div class="form-group">
                    <label for="settingsInactivityMinutes">Auto-lock (minutes)</label>
                    <input type="number" id="settingsInactivityMinutes" min="5" max="240" value="${inactivityMinutes}">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="saveUiPreferencesFromSettings()">Save Preferences</button>
                <button class="action-btn secondary" type="button" onclick="saveInactivitySetting()">Save Auto-lock</button>
                <button class="action-btn secondary" type="button" onclick="openShortcutsModal()">Keyboard Shortcuts</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>System Health</h4>
            <p class="page-subtitle">Run diagnostics, detect data issues early, and export a health report.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="runDataHealthScan()">Run Health Scan</button>
                <button class="action-btn secondary" type="button" onclick="exportDataHealthReport()">Export Health Report</button>
                <button class="action-btn secondary" type="button" onclick="lockSessionNow()">Lock Session Now</button>
            </div>
            <div id="settingsHealthBody"><p class="page-subtitle">Run scan to view current system health.</p></div>
        </div>
        <div class="insight-card">
            <h4>Platform Status</h4>
            <p class="page-subtitle">Quick operational snapshot for enterprise reliability.</p>
            <div id="settingsPlatformStatusBody"></div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="refreshPlatformStatusPanel()">Refresh Status</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>Runtime Diagnostics</h4>
            <p class="page-subtitle">Live browser/device diagnostics to help with performance troubleshooting.</p>
            <div id="settingsRuntimeBody"><p class="page-subtitle">Loading diagnostics...</p></div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="refreshRuntimeDiagnosticsPanel()">Refresh Diagnostics</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>Sync Control</h4>
            <p class="page-subtitle">Manual sync and retry controls for reliability across mobile and desktop.</p>
            <div id="settingsSyncBody"><p class="page-subtitle">Sync status will appear here.</p></div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="refreshSettingsSyncPanel()">Refresh Sync Status</button>
                <button class="action-btn secondary" type="button" onclick="forceRemoteSyncNow()">Sync Now</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>Active Sessions</h4>
            <p class="page-subtitle">View and revoke signed sessions for this account. Admin can view all sessions.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="refreshSettingsSessions()">Refresh Sessions</button>
            </div>
            <div id="settingsSessionsBody"><p class="page-subtitle">Loading sessions...</p></div>
        </div>
        <div class="insight-card">
            <h4>Compatibility Check</h4>
            <p class="page-subtitle">Cross-platform readiness for Android, iOS, Windows, macOS, and Linux browsers.</p>
            <div id="settingsCompatibilityBody"><p class="page-subtitle">Running compatibility checks...</p></div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="runCompatibilityCheck()">Run Compatibility Check</button>
            </div>
        </div>
        ${adminUserControls ? `
        <div class="insight-card">
            <h4>User Management</h4>
            <p class="page-subtitle">Admin can create new user accounts.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsNewUsername">New Username / Full Name</label>
                    <input type="text" id="settingsNewUsername" placeholder="e.g. Team Rhulani User">
                </div>
                <div class="form-group">
                    <label for="settingsNewEmail">Email Address</label>
                    <input type="email" id="settingsNewEmail" placeholder="name@example.com">
                </div>
                <div class="form-group">
                    <label for="settingsUserPassword">Password</label>
                    <input type="password" id="settingsUserPassword" autocomplete="new-password">
                    <div id="settingsUserPasswordStrength" class="password-strength" aria-live="polite"></div>
                </div>
                <div class="form-group">
                    <label for="settingsUserPasswordConfirm">Confirm Password</label>
                    <input type="password" id="settingsUserPasswordConfirm" autocomplete="new-password">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="createUserFromSettings()">Create User</button>
            </div>
            <div id="settingsUserError" class="modal-error" style="display:none;"></div>
        </div>
        ` : ''}
        ${adminUserControls ? `
        <div class="insight-card" id="settingsAdminAccountsCard">
            <h4>Admin-Only Accounts</h4>
            <p class="page-subtitle">Create named admin accounts for Admin page access logging. These accounts can only use Login as Admin.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsAdminUsername">Admin Username / Full Name</label>
                    <input type="text" id="settingsAdminUsername" placeholder="e.g. Admin Thando">
                </div>
                <div class="form-group">
                    <label for="settingsAdminEmail">Admin Email</label>
                    <input type="email" id="settingsAdminEmail" placeholder="admin@example.com">
                </div>
                <div class="form-group">
                    <label for="settingsAdminPassword">Admin Password</label>
                    <input type="password" id="settingsAdminPassword" autocomplete="new-password">
                    <div id="settingsAdminPasswordStrength" class="password-strength" aria-live="polite"></div>
                </div>
                <div class="form-group">
                    <label for="settingsAdminPasswordConfirm">Confirm Admin Password</label>
                    <input type="password" id="settingsAdminPasswordConfirm" autocomplete="new-password">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="createAdminOnlyAccountFromSettings()">Create Admin User Account</button>
            </div>
            <div id="settingsAdminAccountError" class="modal-error" style="display:none;"></div>
        </div>
        ` : ''}
        ${adminControls ? `
        <div class="insight-card register-editor-panel">
            <h4>Team Assignment</h4>
            <p class="page-subtitle">Set the team for a user account.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsTeamUser">User</label>
                    <select id="settingsTeamUser">
                        ${teamAssignmentOptions}
                    </select>
                </div>
                <div class="form-group">
                    <label for="settingsTeamName">Team Name</label>
                    <input type="text" id="settingsTeamName" placeholder="e.g. Team Thato">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveSettingsTeamAssignment()">Save Team</button>
            </div>
            <div id="settingsTeamError" class="modal-error" style="display:none;"></div>
        </div>
        <div class="insight-card">
            <h4>Data Retention</h4>
            <p class="page-subtitle">Purge old leads and DBD records. Admin only.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsRetentionMonths">Delete data older than (months)</label>
                    <input type="number" id="settingsRetentionMonths" min="1" value="6">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="purgeLeadsOlderThan()">Purge Leads</button>
                <button class="action-btn secondary" type="button" onclick="purgeDbdsOlderThan()">Purge DBD Records</button>
            </div>
        </div>
        ${showEncryptedBackup ? `
        <div class="insight-card">
            <h4>Encrypted Backup</h4>
            <p class="page-subtitle">Export or restore encrypted database state for disaster recovery.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="downloadEncryptedBackup()">Download Backup File</button>
                <button class="action-btn secondary" type="button" onclick="exportEncryptedBackup()">Copy Backup JSON</button>
            </div>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="settingsBackupFile">Upload Backup File</label>
                    <input type="file" id="settingsBackupFile" accept=".json,application/json" onchange="loadEncryptedBackupFile(event)">
                </div>
                <div class="form-group">
                    <label for="settingsBackupJson">Restore JSON</label>
                    <textarea id="settingsBackupJson" rows="5" placeholder='Paste backup JSON from export'></textarea>
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="restoreEncryptedBackup()">Restore Backup</button>
            </div>
            <div id="settingsBackupError" class="modal-error" style="display:none;"></div>
        </div>
        ` : ''}
        ` : ''}
        ${adminUserControls ? `
        <div class="insight-card register-editor-panel">
            <h4>Users List</h4>
            <p class="page-subtitle">Manage access status for existing users. Default reset password is <strong>Admin@123</strong>.</p>
            <div class="learning-search" style="margin-bottom:10px;">
                <input type="text" id="settingsUserFilter" placeholder="Search users..." value="${escapeHtml(settingsUserFilter)}" oninput="filterSettingsUsers(this.value)">
            </div>
            <div id="settingsUsersTable"></div>
            <div id="settingsPermissionsEditor"></div>
        </div>
        <div class="insight-card">
            <h4>Security Audit</h4>
            <div id="settingsAuditBody"></div>
        </div>
        ` : ''}
        ${adminControls ? `
        <div class="insight-card">
            <h4>Export Center</h4>
            <p class="page-subtitle">Quick exports and recent activity.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="exportStatsCsv()">Export Stats</button>
                <button class="action-btn secondary" type="button" onclick="exportStatsPdf()">Export Stats PDF</button>
                <button class="action-btn secondary" type="button" onclick="exportDbdsCsv()">Export DBD</button>
                <button class="action-btn secondary" type="button" onclick="exportDbdsPdf()">Export DBD PDF</button>
                <button class="action-btn secondary" type="button" onclick="exportAdminLeadsCsv()">Export Leads</button>
                <button class="action-btn secondary" type="button" onclick="exportAdminLeadsPdf()">Export Leads PDF</button>
            </div>
            <div id="exportHistoryBody"></div>
        </div>
        ` : ''}
    `;
    } catch (error) {
        console.error('renderSettingsPage failed:', error);
        container.innerHTML = `
            <div class="insight-card">
                <h4>Settings Unavailable</h4>
                <p class="page-subtitle">A rendering issue was detected. Please try reopening Settings.</p>
            </div>
        `;
        showToast('Settings failed to render. Please retry.', 'error');
        return;
    }
    try { renderSettingsUsersTableSection(adminUserControls); } catch (error) { console.error('renderSettingsUsersTableSection failed:', error); }
    try { renderSettingsAuditSection(); } catch (error) { console.error('renderSettingsAuditSection failed:', error); }
    try { renderExportHistory(); } catch (error) { console.error('renderExportHistory failed:', error); }
    try { runDataHealthScan(true); } catch (error) { console.error('runDataHealthScan failed:', error); }
    try { refreshPlatformStatusPanel(); } catch (error) { console.error('refreshPlatformStatusPanel failed:', error); }
    try { refreshRuntimeDiagnosticsPanel(); } catch (error) { console.error('refreshRuntimeDiagnosticsPanel failed:', error); }
    try { refreshSettingsSyncPanel(); } catch (error) { console.error('refreshSettingsSyncPanel failed:', error); }
    try { refreshSettingsSessions(true); } catch (error) { console.error('refreshSettingsSessions failed:', error); }
    try { runCompatibilityCheck(true); } catch (error) { console.error('runCompatibilityCheck failed:', error); }
    try { bindPasswordStrengthIndicators(document); } catch (error) { console.error('bindPasswordStrengthIndicators failed:', error); }
}

function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let index = 0;
    let amount = value;
    while (amount >= 1024 && index < units.length - 1) {
        amount /= 1024;
        index += 1;
    }
    return `${amount.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function estimateLocalStorageUsage() {
    try {
        let bytes = 0;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (!key) continue;
            const value = localStorage.getItem(key) || '';
            bytes += (String(key).length + String(value).length) * 2;
        }
        return bytes;
    } catch (_) {
        return 0;
    }
}

function buildDataHealthSnapshot() {
    const leadIds = new Map();
    leadRecords.forEach((lead) => {
        const lid = String(lead?.leadId || '').trim();
        if (!lid) return;
        leadIds.set(lid, (leadIds.get(lid) || 0) + 1);
    });
    const duplicateLids = [...leadIds.entries()].filter(([, count]) => count > 1).length;
    const missingGeo = leadRecords.filter((lead) => {
        const status = String(lead?.geo?.status || '').toLowerCase();
        return !(status === 'ok' || status === 'cached');
    }).length;
    const missingSignature = leadRecords.filter((lead) => !String(lead?.clientSignatureImage || '').trim()).length;
    const invalidLeadEmails = leadRecords.filter((lead) => {
        const email = String(lead?.clientEmailRaw || '').trim();
        if (!email) return false;
        return !isValidEmail(email);
    }).length;
    const leadIdSet = new Set(leadRecords.map((lead) => String(lead?.leadId || '').trim()).filter(Boolean));
    const orphanAppointments = appointmentRecords.filter((appointment) => {
        const lid = String(appointment?.leadId || '').trim();
        return lid && !leadIdSet.has(lid);
    }).length;
    const accounts = getUserAccounts();
    const disabledUsers = Object.values(accounts).filter((account) => account?.active === false).length;
    const teamLeaders = Object.values(accounts).filter((account) => normalizeUserPermissions(account?.permissions, false).admin === true).length;
    const archives = getArchives();
    const archiveRows = archives.reduce((sum, archive) => sum + ((archive?.records || []).length), 0);
    const storageBytes = estimateLocalStorageUsage();
    return {
        scannedAt: new Date().toISOString(),
        leads: leadRecords.length,
        records: jfaRecords.length,
        appointments: appointmentRecords.length,
        notifications: getNotifications().length,
        facilities: facilities.length,
        archives: archives.length,
        archiveRows,
        users: Object.keys(accounts).length,
        disabledUsers,
        teamLeaders,
        duplicateLids,
        missingGeo,
        missingSignature,
        invalidLeadEmails,
        orphanAppointments,
        storageBytes
    };
}

function renderDataHealthSnapshot(snapshot) {
    const container = document.getElementById('settingsHealthBody');
    if (!container || !snapshot) return;
    const issueCount = [
        snapshot.duplicateLids,
        snapshot.missingGeo,
        snapshot.missingSignature,
        snapshot.invalidLeadEmails,
        snapshot.orphanAppointments
    ].reduce((sum, count) => sum + (Number(count) || 0), 0);
    container.innerHTML = `
        <div class="insight-list">
            <span class="insight-chip">Scanned: ${new Date(snapshot.scannedAt).toLocaleString('en-ZA')}</span>
            <span class="insight-chip">Leads: ${snapshot.leads}</span>
            <span class="insight-chip">DBD Records: ${snapshot.records}</span>
            <span class="insight-chip">Appointments: ${snapshot.appointments}</span>
            <span class="insight-chip">Notifications: ${snapshot.notifications}</span>
            <span class="insight-chip">Facilities: ${snapshot.facilities}</span>
            <span class="insight-chip">Users: ${snapshot.users}</span>
            <span class="insight-chip">Team Leaders: ${snapshot.teamLeaders}</span>
            <span class="insight-chip">Disabled Users: ${snapshot.disabledUsers}</span>
            <span class="insight-chip">Archive Batches: ${snapshot.archives}</span>
            <span class="insight-chip">Archive Rows: ${snapshot.archiveRows}</span>
            <span class="insight-chip">Storage Used: ${formatBytes(snapshot.storageBytes)}</span>
            <span class="insight-chip ${issueCount > 0 ? 'danger' : ''}">Quality Issues: ${issueCount}</span>
            <span class="insight-chip">Duplicate LIDs: ${snapshot.duplicateLids}</span>
            <span class="insight-chip">Missing Geo: ${snapshot.missingGeo}</span>
            <span class="insight-chip">Missing Signature: ${snapshot.missingSignature}</span>
            <span class="insight-chip">Invalid Lead Emails: ${snapshot.invalidLeadEmails}</span>
            <span class="insight-chip">Orphan Appointments: ${snapshot.orphanAppointments}</span>
        </div>
    `;
}

function runDataHealthScan(silent = false) {
    const snapshot = buildDataHealthSnapshot();
    renderDataHealthSnapshot(snapshot);
    if (!silent) {
        const issueCount = [
            snapshot.duplicateLids,
            snapshot.missingGeo,
            snapshot.missingSignature,
            snapshot.invalidLeadEmails,
            snapshot.orphanAppointments
        ].reduce((sum, count) => sum + (Number(count) || 0), 0);
        showToast(issueCount > 0 ? `Health scan complete. ${issueCount} issues flagged.` : 'Health scan complete. No issues flagged.', issueCount > 0 ? 'error' : 'success');
    }
}

function buildPlatformStatusSnapshot() {
    const offlineEl = document.getElementById('offlineStatus');
    const lastSaved = offlineEl?.getAttribute('data-last-saved') || '--:--';
    const key = normalizeJfaName(appUser || '');
    const accounts = getUserAccounts();
    const account = accounts[key] || null;
    const remoteAuth = getRemoteAuthState();
    return {
        build: APP_BUILD,
        online: navigator.onLine,
        remoteAllowed: isRemoteSyncAllowed(),
        remoteReady: remoteSyncReady,
        remoteInFlight: remoteSyncInFlight,
        remoteSignedIn: Boolean(remoteAuth.accessToken && remoteAuth.sessionId && remoteAuth.accessExpAt > Date.now()),
        serviceWorkerReady: Boolean(navigator.serviceWorker?.controller),
        storageUsed: formatBytes(estimateLocalStorageUsage()),
        lastSaved,
        user: formatJfaName(appUser || 'Guest'),
        lastLoginAt: account?.lastLoginAt || ''
    };
}

function renderPlatformStatusPanel(snapshot) {
    const container = document.getElementById('settingsPlatformStatusBody');
    if (!container || !snapshot) return;
    const remoteStatus = !snapshot.remoteAllowed
        ? 'Offline only'
        : snapshot.remoteInFlight
            ? 'Sync in progress'
            : snapshot.remoteReady
                ? 'Connected'
                : 'Not connected';
    container.innerHTML = `
        <div class="insight-list">
            <span class="insight-chip">Build: v${escapeHtml(snapshot.build)}</span>
            <span class="insight-chip ${snapshot.online ? '' : 'danger'}">Network: ${snapshot.online ? 'Online' : 'Offline'}</span>
            <span class="insight-chip">Remote Sync: ${remoteStatus}</span>
            <span class="insight-chip ${snapshot.remoteSignedIn ? '' : 'danger'}">Remote Session: ${snapshot.remoteSignedIn ? 'Signed In' : 'Not Signed In'}</span>
            <span class="insight-chip ${snapshot.serviceWorkerReady ? '' : 'danger'}">Service Worker: ${snapshot.serviceWorkerReady ? 'Active' : 'Unavailable'}</span>
            <span class="insight-chip">Storage Used: ${snapshot.storageUsed}</span>
            <span class="insight-chip">Last Saved: ${snapshot.lastSaved}</span>
            <span class="insight-chip">Current User: ${escapeHtml(snapshot.user)}</span>
            <span class="insight-chip">Last Login: ${snapshot.lastLoginAt ? new Date(snapshot.lastLoginAt).toLocaleString('en-ZA') : '—'}</span>
        </div>
    `;
}

function refreshPlatformStatusPanel() {
    renderPlatformStatusPanel(buildPlatformStatusSnapshot());
}

function refreshSettingsSyncPanel() {
    const container = document.getElementById('settingsSyncBody');
    if (!container) return;
    const queuedWrites = storageWriteQueue.size;
    const remoteSignedIn = Boolean(getRemoteAuthState().accessToken);
    const syncAtRaw = localStorage.getItem(STORAGE_KEYS.remoteSyncAt) || '';
    const syncAt = syncAtRaw ? new Date(syncAtRaw).toLocaleString('en-ZA') : 'Never';
    container.innerHTML = `
        <div class="insight-list">
            <span class="insight-chip">Local Write Queue: ${queuedWrites}</span>
            <span class="insight-chip ${navigator.onLine ? '' : 'danger'}">Network: ${navigator.onLine ? 'Online' : 'Offline'}</span>
            <span class="insight-chip ${remoteSyncReady ? '' : 'danger'}">Remote Sync: ${remoteSyncReady ? 'Ready' : 'Not Ready'}</span>
            <span class="insight-chip ${remoteSignedIn ? '' : 'danger'}">Signed Session: ${remoteSignedIn ? 'Active' : 'Missing'}</span>
            <span class="insight-chip">Last Remote Sync: ${escapeHtml(syncAt)}</span>
        </div>
    `;
}

function buildRuntimeDiagnosticsSnapshot() {
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
    const nav = navigator || {};
    const connection = nav.connection || nav.mozConnection || nav.webkitConnection;
    const memory = performance && performance.memory
        ? {
            used: performance.memory.usedJSHeapSize,
            total: performance.memory.totalJSHeapSize,
            limit: performance.memory.jsHeapSizeLimit
        }
        : null;
    return {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
        language: nav.language || 'Unknown',
        platform: nav.platform || 'Unknown',
        viewport: `${viewportWidth} x ${viewportHeight}`,
        colorScheme: document.body.classList.contains('dark') ? 'Dark' : 'Light',
        reducedMotion: document.body.classList.contains('reduce-motion') ? 'Enabled' : 'Disabled',
        deviceMemory: Number(nav.deviceMemory || 0),
        cpuCores: Number(nav.hardwareConcurrency || 0),
        connection: connection?.effectiveType || (navigator.onLine ? 'online' : 'offline'),
        heapUsed: memory ? formatBytes(memory.used) : 'Unavailable',
        heapTotal: memory ? formatBytes(memory.total) : 'Unavailable',
        heapLimit: memory ? formatBytes(memory.limit) : 'Unavailable',
        checkedAt: new Date().toISOString()
    };
}

function refreshRuntimeDiagnosticsPanel() {
    const container = document.getElementById('settingsRuntimeBody');
    if (!container) return;
    const snapshot = buildRuntimeDiagnosticsSnapshot();
    container.innerHTML = `
        <div class="insight-list">
            <span class="insight-chip">Checked: ${new Date(snapshot.checkedAt).toLocaleString('en-ZA')}</span>
            <span class="insight-chip">Theme: ${snapshot.colorScheme}</span>
            <span class="insight-chip">Viewport: ${snapshot.viewport}</span>
            <span class="insight-chip">Timezone: ${escapeHtml(snapshot.timezone)}</span>
            <span class="insight-chip">Language: ${escapeHtml(snapshot.language)}</span>
            <span class="insight-chip">Platform: ${escapeHtml(snapshot.platform)}</span>
            <span class="insight-chip">Connection: ${escapeHtml(snapshot.connection)}</span>
            <span class="insight-chip">Device Memory: ${snapshot.deviceMemory > 0 ? `${snapshot.deviceMemory} GB` : 'Unknown'}</span>
            <span class="insight-chip">CPU Cores: ${snapshot.cpuCores > 0 ? snapshot.cpuCores : 'Unknown'}</span>
            <span class="insight-chip">Reduce Motion: ${snapshot.reducedMotion}</span>
            <span class="insight-chip">JS Heap Used: ${snapshot.heapUsed}</span>
            <span class="insight-chip">JS Heap Total: ${snapshot.heapTotal}</span>
            <span class="insight-chip">JS Heap Limit: ${snapshot.heapLimit}</span>
        </div>
    `;
}

async function forceRemoteSyncNow() {
    if (!navigator.onLine) {
        showToast('You are offline. Remote sync will run when connection returns.', 'error');
        refreshSettingsSyncPanel();
        return;
    }
    if (!isRemoteSyncAllowed()) {
        showToast('Server mode is disabled. Running local save only.', 'error');
        refreshSettingsSyncPanel();
        return;
    }
    try {
        setSyncState('syncing');
        await pushStateToRemote();
        refreshSettingsSyncPanel();
        refreshPlatformStatusPanel();
        showToast('Manual sync completed.', 'success');
    } catch (_) {
        refreshSettingsSyncPanel();
        showToast('Manual sync failed.', 'error');
    }
}

function renderSettingsSessionsList(items = [], errorText = '') {
    const container = document.getElementById('settingsSessionsBody');
    if (!container) return;
    if (errorText) {
        container.innerHTML = `<p class="page-subtitle">${escapeHtml(errorText)}</p>`;
        return;
    }
    if (!Array.isArray(items) || !items.length) {
        container.innerHTML = '<p class="page-subtitle">No active signed sessions found.</p>';
        return;
    }
    const currentSessionId = getRemoteAuthState().sessionId;
    container.innerHTML = `
        <div class="mini-table">
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Role</th>
                        <th>Team</th>
                        <th>IP</th>
                        <th>Last Seen</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${items.map((session) => {
                        const sid = String(session?.session_id || '');
                        const isCurrent = sid && sid === currentSessionId;
                        const revoked = Boolean(session?.revoked_at);
                        return `
                            <tr>
                                <td>${escapeHtml(formatJfaName(session?.username || session?.user_key || '—'))}${isCurrent ? ' (Current)' : ''}</td>
                                <td>${escapeHtml(String(session?.role || 'PERSONAL'))}</td>
                                <td>${escapeHtml(String(session?.team || '—'))}</td>
                                <td>${escapeHtml(String(session?.ip_address || '—'))}</td>
                                <td>${session?.last_seen_at ? new Date(session.last_seen_at).toLocaleString('en-ZA') : '—'}</td>
                                <td>${revoked ? 'Revoked' : 'Active'}</td>
                                <td>
                                    <button class="action-btn secondary" type="button" ${revoked ? 'disabled' : ''} onclick="revokeSettingsSession('${encodeURIComponent(sid)}')">
                                        Revoke
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

async function refreshSettingsSessions(silent = false) {
    const container = document.getElementById('settingsSessionsBody');
    if (!container) return;
    container.innerHTML = `
        <div class="skeleton-grid">
            <div class="skeleton" style="height:12px;"></div>
            <div class="skeleton" style="height:12px;"></div>
            <div class="skeleton" style="height:12px;"></div>
            <div class="skeleton" style="height:12px;"></div>
        </div>
    `;
    if (!isRemoteSyncAllowed()) {
        renderSettingsSessionsList([], 'Session monitoring requires secure server mode.');
        return;
    }
    if (!(await refreshRemoteAccessTokenIfNeeded())) {
        renderSettingsSessionsList([], 'No active signed session. Sign in again to view sessions.');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/sessions?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data?.error || 'Failed to load sessions');
        }
        const data = await response.json().catch(() => ({}));
        renderSettingsSessionsList(Array.isArray(data?.items) ? data.items : []);
        if (!silent) showToast('Sessions refreshed.', 'success');
    } catch (error) {
        renderSettingsSessionsList([], String(error?.message || 'Failed to load sessions.'));
        if (!silent) showToast('Unable to load sessions.', 'error');
    }
}

async function revokeSettingsSession(encodedSessionId) {
    const sessionId = decodeURIComponent(String(encodedSessionId || ''));
    if (!sessionId) return;
    if (!isRemoteSyncAllowed()) return;
    if (!(await refreshRemoteAccessTokenIfNeeded())) {
        showToast('Session expired. Sign in again.', 'error');
        return;
    }
    const ok = await openAppConfirmModal({
        title: 'Revoke Session',
        message: 'Revoke this signed session now?',
        confirmText: 'Revoke',
        cancelText: 'Cancel'
    });
    if (!ok) return;
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/sessions/${encodeURIComponent(sessionId)}?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            method: 'DELETE',
            headers: buildRemoteHeaders()
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data?.error || 'Failed to revoke session');
        }
        showToast('Session revoked.', 'success');
        const currentSessionId = getRemoteAuthState().sessionId;
        if (currentSessionId && sessionId === currentSessionId) {
            logoutAppUser();
            return;
        }
        refreshSettingsSessions(true);
    } catch (error) {
        showToast(String(error?.message || 'Failed to revoke session.'), 'error');
    }
}

function detectOsName() {
    const ua = String(navigator.userAgent || '').toLowerCase();
    const platform = String(navigator.platform || '').toLowerCase();
    if (ua.includes('android')) return 'Android';
    if (/iphone|ipad|ipod/.test(ua) || /iphone|ipad|ipod/.test(platform)) return 'iOS';
    if (ua.includes('windows') || platform.includes('win')) return 'Windows';
    if (ua.includes('mac os') || platform.includes('mac')) return 'macOS';
    if (ua.includes('linux') || platform.includes('linux')) return 'Linux';
    return 'Unknown';
}

function detectBrowserName() {
    const ua = String(navigator.userAgent || '');
    if (ua.includes('Edg/')) return 'Edge';
    if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
    if (ua.includes('Chrome/') && !ua.includes('Edg/')) return 'Chrome';
    if (ua.includes('Safari/') && !ua.includes('Chrome/')) return 'Safari';
    if (ua.includes('Firefox/')) return 'Firefox';
    return 'Unknown';
}

async function buildCompatibilitySnapshot() {
    const displayMode = window.matchMedia?.('(display-mode: standalone)').matches ? 'standalone' : 'browser';
    const isIosStandalone = typeof navigator.standalone !== 'undefined' && Boolean(navigator.standalone);
    const pwaInstalled = displayMode === 'standalone' || isIosStandalone;
    const storageEstimate = navigator.storage?.estimate ? await navigator.storage.estimate().catch(() => null) : null;
    const quota = Number(storageEstimate?.quota || 0);
    const usage = Number(storageEstimate?.usage || 0);
    const storagePercent = quota > 0 ? Math.round((usage / quota) * 100) : 0;
    const manifestLinked = Boolean(document.querySelector('link[rel="manifest"]'));
    const swSupported = 'serviceWorker' in navigator;
    const swControlled = Boolean(navigator.serviceWorker?.controller);
    const installPromptSupported = Boolean(deferredInstallPromptEvent) || Boolean(window.matchMedia?.('(display-mode: browser)').matches);
    return {
        os: detectOsName(),
        browser: detectBrowserName(),
        online: navigator.onLine,
        pwaInstalled,
        displayMode: pwaInstalled ? 'standalone' : displayMode,
        manifestLinked,
        swSupported,
        swControlled,
        installPromptSupported,
        notificationsSupported: 'Notification' in window,
        geolocationSupported: 'geolocation' in navigator,
        pushSupported: 'PushManager' in window,
        shareSupported: typeof navigator.share === 'function',
        clipboardSupported: Boolean(navigator.clipboard),
        indexedDbSupported: Boolean(window.indexedDB),
        touchSupported: (navigator.maxTouchPoints || 0) > 0,
        storageQuota: quota,
        storageUsage: usage,
        storagePercent
    };
}

function renderCompatibilityPanel(snapshot) {
    const container = document.getElementById('settingsCompatibilityBody');
    if (!container || !snapshot) return;
    const ok = (value) => value ? '' : 'danger';
    const yesNo = (value) => value ? 'Yes' : 'No';
    container.innerHTML = `
        <div class="insight-list">
            <span class="insight-chip">OS: ${escapeHtml(snapshot.os)}</span>
            <span class="insight-chip">Browser: ${escapeHtml(snapshot.browser)}</span>
            <span class="insight-chip ${snapshot.online ? '' : 'danger'}">Network: ${snapshot.online ? 'Online' : 'Offline'}</span>
            <span class="insight-chip ${ok(snapshot.pwaInstalled)}">PWA Installed: ${yesNo(snapshot.pwaInstalled)}</span>
            <span class="insight-chip">Display Mode: ${escapeHtml(snapshot.displayMode)}</span>
            <span class="insight-chip ${ok(snapshot.manifestLinked)}">Manifest Linked: ${yesNo(snapshot.manifestLinked)}</span>
            <span class="insight-chip ${ok(snapshot.swSupported)}">Service Worker Support: ${yesNo(snapshot.swSupported)}</span>
            <span class="insight-chip ${ok(snapshot.swControlled)}">Service Worker Active: ${yesNo(snapshot.swControlled)}</span>
            <span class="insight-chip ${ok(snapshot.installPromptSupported)}">Install Prompt Path: ${yesNo(snapshot.installPromptSupported)}</span>
            <span class="insight-chip ${ok(snapshot.notificationsSupported)}">Notifications API: ${yesNo(snapshot.notificationsSupported)}</span>
            <span class="insight-chip ${ok(snapshot.geolocationSupported)}">Geolocation API: ${yesNo(snapshot.geolocationSupported)}</span>
            <span class="insight-chip ${ok(snapshot.pushSupported)}">Push API: ${yesNo(snapshot.pushSupported)}</span>
            <span class="insight-chip ${ok(snapshot.shareSupported)}">Share API: ${yesNo(snapshot.shareSupported)}</span>
            <span class="insight-chip ${ok(snapshot.clipboardSupported)}">Clipboard API: ${yesNo(snapshot.clipboardSupported)}</span>
            <span class="insight-chip ${ok(snapshot.indexedDbSupported)}">IndexedDB: ${yesNo(snapshot.indexedDbSupported)}</span>
            <span class="insight-chip">Touch Input: ${yesNo(snapshot.touchSupported)}</span>
            <span class="insight-chip">Storage Used: ${formatBytes(snapshot.storageUsage)} / ${snapshot.storageQuota ? formatBytes(snapshot.storageQuota) : 'Unknown'}</span>
            <span class="insight-chip ${snapshot.storagePercent >= 90 ? 'danger' : ''}">Storage Load: ${snapshot.storageQuota ? `${snapshot.storagePercent}%` : 'Unknown'}</span>
        </div>
    `;
}

async function runCompatibilityCheck(silent = false) {
    const snapshot = await buildCompatibilitySnapshot();
    renderCompatibilityPanel(snapshot);
    if (!silent) {
        const blockers = [
            !snapshot.manifestLinked,
            !snapshot.swSupported,
            snapshot.storageQuota > 0 && snapshot.storagePercent >= 90
        ].filter(Boolean).length;
        showToast(blockers ? `Compatibility check complete: ${blockers} issue(s) flagged.` : 'Compatibility check complete: all core checks passed.', blockers ? 'error' : 'success');
    }
}

function exportDataHealthReport() {
    const snapshot = buildDataHealthSnapshot();
    const headers = ['Metric', 'Value'];
    const rows = [
        ['Scanned At', new Date(snapshot.scannedAt).toLocaleString('en-ZA')],
        ['Leads', snapshot.leads],
        ['DBD Records', snapshot.records],
        ['Appointments', snapshot.appointments],
        ['Notifications', snapshot.notifications],
        ['Facilities', snapshot.facilities],
        ['Users', snapshot.users],
        ['Team Leaders', snapshot.teamLeaders],
        ['Disabled Users', snapshot.disabledUsers],
        ['Archive Batches', snapshot.archives],
        ['Archive Rows', snapshot.archiveRows],
        ['Storage Used', formatBytes(snapshot.storageBytes)],
        ['Duplicate LIDs', snapshot.duplicateLids],
        ['Missing Geo', snapshot.missingGeo],
        ['Missing Signature', snapshot.missingSignature],
        ['Invalid Lead Emails', snapshot.invalidLeadEmails],
        ['Orphan Appointments', snapshot.orphanAppointments]
    ];
    exportCsvWithHeaders(headers, rows, `system-health-${todayKey()}.csv`, 'System Health Report');
    logAudit('Exported system health report', `Issues: ${snapshot.duplicateLids + snapshot.missingGeo + snapshot.missingSignature + snapshot.invalidLeadEmails + snapshot.orphanAppointments}`);
    logExportHistory('System Health Export', rows.length);
}

function lockSessionNow() {
    if (!appUser) {
        showToast('No active session to lock.', 'error');
        return;
    }
    forceSessionLockDueToInactivity();
}

function renderSettingsUsersTable(adminControls) {
    const accounts = getUserAccounts();
    const query = settingsUserFilter.trim().toLowerCase();
    const rows = Object.entries(accounts)
        .map(([key, account]) => ({ key, ...(account || {}) }))
        .filter((entry) => {
            if (!query) return true;
            const name = String(entry.username || entry.key || '').toLowerCase();
            return name.includes(query);
        })
        .sort((a, b) => String(a.username || a.key).localeCompare(String(b.username || b.key), 'en', { sensitivity: 'base' }));
    if (!rows.length) {
        return '<p class="page-subtitle">No users found.</p>';
    }
    return `
        <div class="mini-table">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Access</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows.map((entry) => {
                        const username = entry.username || entry.key;
                        const encoded = encodeURIComponent(username);
                        const isAdminUser = normalizeJfaName(username) === 'admin';
                        const isAdminOnly = entry.adminOnly === true;
                        const isActive = entry.active !== false;
                        const canManage = adminControls && !isAdminUser;
                        const statusClass = isActive ? 'on' : 'under';
                        const statusLabel = isActive ? 'Active' : 'Disabled';
                        const permissions = normalizeUserPermissions(entry.permissions, isAdminUser);
                        const accessSummary = USER_PERMISSION_KEYS
                            .filter((permission) => permissions[permission])
                            .map((permission) => USER_PERMISSION_LABELS[permission] || permission)
                            .join(', ') || 'None';
                        return `
                            <tr>
                                <td>${escapeHtml(formatJfaName(username))}</td>
                                <td>${isAdminUser || isAdminOnly ? 'Admin' : permissions.admin ? 'Team Leader' : 'User'}</td>
                                <td><span class="admin-jfa-status ${statusClass}">${statusLabel}</span></td>
                                <td>${entry.createdAt ? new Date(entry.createdAt).toLocaleDateString('en-ZA') : '—'}</td>
                                <td>${entry.lastLoginAt ? new Date(entry.lastLoginAt).toLocaleString('en-ZA') : '—'}</td>
                                <td>${escapeHtml(accessSummary)}</td>
                                <td>
                                    <div class="menu-page-actions">
                                        <button class="action-btn secondary" type="button" ${canManage ? '' : 'disabled'} onclick="openSettingsPermissionsEditor('${encoded}')">Manage Access</button>
                                        <button class="action-btn secondary" type="button" ${canManage ? '' : 'disabled'} onclick="resetSettingsUserPassword('${encoded}')">Reset Password</button>
                                        <button class="action-btn secondary" type="button" ${canManage ? '' : 'disabled'} onclick="toggleSettingsUserState('${encoded}')">${isActive ? 'Disable' : 'Enable'}</button>
                                        <button class="action-btn secondary" type="button" ${canManage ? '' : 'disabled'} onclick="deleteSettingsUser('${encoded}')">Delete</button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function renderSettingsUsersTableSection(adminControls = hasAdminUserSettingsAccess()) {
    const container = document.getElementById('settingsUsersTable');
    if (!container) return;
    if (!hasAdminUserSettingsAccess()) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = renderSettingsUsersTable(adminControls);
}

function filterSettingsUsers(value = '') {
    if (!hasAdminUserSettingsAccess()) return;
    settingsUserFilter = String(value || '');
    renderSettingsUsersTableSection();
}

function openSettingsPermissionsEditor(encodedUsername) {
    const container = document.getElementById('settingsPermissionsEditor');
    if (!container) return;
    if (!hasAdminUserSettingsAccess()) {
        setSettingsError('settingsUserError', 'Only admin can manage access.');
        return;
    }
    const username = decodeURIComponent(encodedUsername || '');
    const key = normalizeJfaName(username);
    if (!key || key === 'admin') {
        setSettingsError('settingsUserError', 'Admin access is fixed and cannot be edited here.');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        setSettingsError('settingsUserError', 'User not found.');
        return;
    }
    settingsAccessTarget = key;
    const permissions = normalizeUserPermissions(account.permissions, false);
    const editableKeys = USER_PERMISSION_KEYS.filter((permissionKey) => permissionKey !== 'settings');
    container.innerHTML = `
        <div class="insight-card" style="margin-top:12px;">
            <h4>Manage Access: ${escapeHtml(formatJfaName(account.username || username))}</h4>
            <div class="menu-page-actions">
                ${editableKeys.map((permissionKey) => `
                    <label class="radio-option">
                        <input type="checkbox" data-permission-key="${permissionKey}" ${permissions[permissionKey] ? 'checked' : ''}>
                        <span class="radio-label">${escapeHtml(USER_PERMISSION_LABELS[permissionKey] || permissionKey)}</span>
                    </label>
                `).join('')}
            </div>
            <p class="page-subtitle">Settings access stays enabled so users can update their own password.</p>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveSettingsUserPermissions('${encodedUsername}')">Save Access</button>
                <button class="action-btn secondary" type="button" onclick="closeSettingsPermissionsEditor()">Cancel</button>
            </div>
            <div id="settingsPermissionError" class="modal-error" style="display:none;"></div>
        </div>
    `;
}

function closeSettingsPermissionsEditor() {
    const container = document.getElementById('settingsPermissionsEditor');
    if (!container) return;
    settingsAccessTarget = '';
    container.innerHTML = '';
}

function saveSettingsUserPermissions(encodedUsername) {
    if (!hasAdminUserSettingsAccess()) {
        setSettingsError('settingsUserError', 'Only admin can manage access.');
        return;
    }
    const username = decodeURIComponent(encodedUsername || '');
    const key = normalizeJfaName(username);
    if (!key || key === 'admin') {
        setSettingsError('settingsUserError', 'Admin access cannot be changed here.');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        setSettingsError('settingsUserError', 'User not found.');
        return;
    }
    const checkboxes = Array.from(document.querySelectorAll('#settingsPermissionsEditor [data-permission-key]'));
    const nextPermissions = getDefaultPermissions(false);
    checkboxes.forEach((checkbox) => {
        const permissionKey = checkbox.getAttribute('data-permission-key');
        if (USER_PERMISSION_KEYS.includes(permissionKey)) {
            nextPermissions[permissionKey] = checkbox.checked;
        }
    });
    account.permissions = normalizeUserPermissions(nextPermissions, false);
    account.updatedAt = new Date().toISOString();
    account.updatedBy = formatJfaName(appUser || 'admin');
    accounts[key] = account;
    saveUserAccounts(accounts);
    setSettingsError('settingsUserError', '');
    logUserMgmtAction('Permissions updated', `Account: ${formatJfaName(account.username || username)} -> ${USER_PERMISSION_KEYS.filter((permissionKey) => account.permissions[permissionKey]).join(', ')}`);
    showToast(`Access updated for ${formatJfaName(account.username || username)}.`, 'success');
    closeSettingsPermissionsEditor();
    renderSettingsUsersTableSection(true);
    renderSettingsAuditSection();
    updatePermissionDrivenUi();
}

function renderSettingsAuditSection() {
    const container = document.getElementById('settingsAuditBody');
    if (!container) return;
    if (!hasAdminUserSettingsAccess()) {
        container.innerHTML = '';
        return;
    }
    const items = getUserMgmtAuditLog().slice(0, 12);
    if (!items.length) {
        container.innerHTML = '<p class="page-subtitle">No security actions logged yet.</p>';
        return;
    }
    container.innerHTML = `
        <div class="mini-table">
            <table>
                <thead>
                    <tr>
                        <th>When</th>
                        <th>Action</th>
                        <th>Detail</th>
                        <th>By</th>
                    </tr>
                </thead>
                <tbody>
                    ${items.map((entry) => `
                        <tr>
                            <td>${entry.timestamp ? new Date(entry.timestamp).toLocaleString('en-ZA') : '—'}</td>
                            <td>${escapeHtml(entry.action || '—')}</td>
                            <td>${escapeHtml(entry.detail || '—')}</td>
                            <td>${escapeHtml(entry.by || '—')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function renderExportHistory() {
    const container = document.getElementById('exportHistoryBody');
    if (!container) return;
    if (!exportHistory.length) {
        container.innerHTML = '<p class="page-subtitle">No exports yet.</p>';
        return;
    }
    container.innerHTML = `
        <div class="mini-table">
            <table>
                <thead>
                    <tr>
                        <th>When</th>
                        <th>Export</th>
                        <th>Rows</th>
                    </tr>
                </thead>
                <tbody>
                    ${exportHistory.map((entry) => `
                        <tr>
                            <td>${entry.timestamp ? new Date(entry.timestamp).toLocaleString('en-ZA') : '—'}</td>
                            <td>${escapeHtml(entry.label || '—')}</td>
                            <td>${entry.count || 0}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function saveSettingsTeamAssignment() {
    const errorId = 'settingsTeamError';
    if (!hasMasterAdminAccess()) {
        setSettingsError(errorId, 'Only admin can assign teams.');
        return;
    }
    const userEl = document.getElementById('settingsTeamUser');
    const teamEl = document.getElementById('settingsTeamName');
    const username = formatJfaName(userEl?.value || '');
    const team = (teamEl?.value || '').trim();
    if (!username) {
        setSettingsError(errorId, 'Select a user.');
        return;
    }
    if (!team) {
        setSettingsError(errorId, 'Enter a team name.');
        return;
    }
    const key = normalizeJfaName(username);
    const profile = ensureJfaProfile(username) || {};
    profile.team = team;
    profile.fullName = formatJfaName(profile.fullName || username);
    jfaProfiles[key] = profile;
    saveJfaProfiles();
    setSettingsError(errorId, '');
    logUserMgmtAction('Team assigned', `Account: ${username} -> ${team}`);
    logAudit('Team assignment updated', `${formatJfaName(username)} -> ${team}`);
    showToast('Team assignment saved.', 'success');
    renderSettingsPage();
}

function getRetentionCutoffDate(months) {
    const now = new Date();
    const cutoff = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    cutoff.setMonth(cutoff.getMonth() - months);
    return cutoff;
}

async function purgeLeadsOlderThan() {
    if (!hasMasterAdminAccess()) {
        showToast('Only admin can purge leads.', 'error');
        return;
    }
    const monthsEl = document.getElementById('settingsRetentionMonths');
    const months = Math.max(1, Number(monthsEl?.value || 0));
    if (!Number.isFinite(months) || months < 1) {
        showToast('Enter a valid retention period.', 'error');
        return;
    }
    const confirmed = await openAppConfirmModal({
        title: 'Purge Leads?',
        message: `Permanently delete leads older than ${months} month(s)?`,
        confirmText: 'Purge',
        cancelText: 'Cancel'
    });
    if (!confirmed) return;
    const cutoff = getRetentionCutoffDate(months);
    const before = leadRecords.length;
    leadRecords = leadRecords.filter((lead) => {
        if (!lead.timestamp) return true;
        return new Date(lead.timestamp) >= cutoff;
    });
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    logAudit('Leads purged', `Older than ${months} months. Removed: ${before - leadRecords.length}`);
    showToast('Old leads removed.', 'success');
    renderAdminMasterLogger();
}

async function purgeDbdsOlderThan() {
    if (!hasMasterAdminAccess()) {
        showToast('Only admin can purge DBD records.', 'error');
        return;
    }
    const monthsEl = document.getElementById('settingsRetentionMonths');
    const months = Math.max(1, Number(monthsEl?.value || 0));
    if (!Number.isFinite(months) || months < 1) {
        showToast('Enter a valid retention period.', 'error');
        return;
    }
    const confirmed = await openAppConfirmModal({
        title: 'Purge DBD Records?',
        message: `Permanently delete DBD records older than ${months} month(s)?`,
        confirmText: 'Purge',
        cancelText: 'Cancel'
    });
    if (!confirmed) return;
    const cutoff = getRetentionCutoffDate(months);
    const beforeLive = jfaRecords.length;
    jfaRecords = jfaRecords.filter((record) => {
        if (!record.timestamp) return true;
        return new Date(record.timestamp) >= cutoff;
    });
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));

    const archives = getArchives();
    let removed = 0;
    const updated = archives
        .map((archive) => {
            const records = (archive.records || []).filter((record) => {
                if (!record.timestamp) return true;
                return new Date(record.timestamp) >= cutoff;
            });
            removed += (archive.records || []).length - records.length;
            return { ...archive, records };
        })
        .filter((archive) => (archive.records || []).length);
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(updated));
    logAudit('DBD purged', `Older than ${months} months. Removed: ${beforeLive - jfaRecords.length + removed}`);
    showToast('Old DBD records removed.', 'success');
    renderArchives();
    updateStatistics();
}

async function exportEncryptedBackup() {
    if (!hasMasterAdminAccess()) {
        showToast('Only admin can export backups.', 'error');
        return;
    }
    if (!isRemoteSyncAllowed()) {
        setSettingsError('settingsBackupError', 'Backup export requires secure server connection.');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/backup?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data?.backup) {
            throw new Error(data?.error || 'Backup export failed.');
        }
        const backupText = JSON.stringify({
            scope: REMOTE_STATE_SCOPE,
            branding: {
                brand: EXPORT_BRAND_NAME,
                logo: EXPORT_LOGO_FILE
            },
            backup: data.backup
        }, null, 2);
        copyToClipboard(backupText, 'Encrypted backup copied to clipboard.');
        setSettingsError('settingsBackupError', '');
    } catch (error) {
        setSettingsError('settingsBackupError', String(error?.message || 'Backup export failed.'));
    }
}

async function downloadEncryptedBackup() {
    if (!hasMasterAdminAccess()) {
        showToast('Only admin can export backups.', 'error');
        return;
    }
    if (!isRemoteSyncAllowed()) {
        setSettingsError('settingsBackupError', 'Backup export requires secure server connection.');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/backup?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data?.backup) {
            throw new Error(data?.error || 'Backup export failed.');
        }
        const payload = {
            scope: REMOTE_STATE_SCOPE,
            branding: {
                brand: EXPORT_BRAND_NAME,
                logo: EXPORT_LOGO_FILE
            },
            backup: data.backup
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const safeScope = String(REMOTE_STATE_SCOPE || 'matla').replace(/[^a-z0-9_-]/gi, '-').toLowerCase();
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        const a = document.createElement('a');
        a.href = url;
        a.download = `matla-backup-${safeScope}-${stamp}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        setSettingsError('settingsBackupError', '');
        showToast('Encrypted backup file downloaded.', 'success');
    } catch (error) {
        setSettingsError('settingsBackupError', String(error?.message || 'Backup export failed.'));
    }
}

async function loadEncryptedBackupFile(event) {
    const file = event?.target?.files?.[0];
    if (!file) return;
    if (!/\.json$/i.test(file.name) && file.type && file.type !== 'application/json') {
        setSettingsError('settingsBackupError', 'Please select a valid .json backup file.');
        return;
    }
    try {
        const text = await file.text();
        const input = document.getElementById('settingsBackupJson');
        if (input) input.value = text;
        setSettingsError('settingsBackupError', '');
        showToast('Backup file loaded. Click Restore Backup to apply.', 'success');
    } catch (_) {
        setSettingsError('settingsBackupError', 'Unable to read backup file.');
    }
}

async function restoreEncryptedBackup() {
    if (!hasMasterAdminAccess()) {
        showToast('Only admin can restore backups.', 'error');
        return;
    }
    const input = document.getElementById('settingsBackupJson');
    const raw = (input?.value || '').trim();
    if (!raw) {
        setSettingsError('settingsBackupError', 'Paste backup JSON first.');
        return;
    }
    if (!isRemoteSyncAllowed()) {
        setSettingsError('settingsBackupError', 'Backup restore requires secure server connection.');
        return;
    }
    let parsed = null;
    try {
        parsed = JSON.parse(raw);
    } catch (_) {
        setSettingsError('settingsBackupError', 'Invalid JSON.');
        return;
    }
    const scope = String(parsed?.scope || REMOTE_STATE_SCOPE).trim();
    const backup = parsed?.backup;
    if (!scope || !backup || typeof backup !== 'object') {
        setSettingsError('settingsBackupError', 'Missing scope/backup fields.');
        return;
    }
    const confirmation = prompt('Type RESTORE to confirm encrypted state restore.');
    if (confirmation !== 'RESTORE') {
        setSettingsError('settingsBackupError', 'Restore cancelled.');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/restore`, {
            method: 'POST',
            headers: buildRemoteHeaders(),
            body: JSON.stringify({
                scope,
                backup,
                confirmPhrase: 'RESTORE'
            })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data?.error || 'Backup restore failed.');
        }
        await refreshRemoteState();
        setSettingsError('settingsBackupError', '');
        if (input) input.value = '';
        showToast('Encrypted backup restored successfully.', 'success');
        updateStatistics();
    } catch (error) {
        setSettingsError('settingsBackupError', String(error?.message || 'Backup restore failed.'));
    }
}

function setSettingsError(targetId, message = '') {
    const el = document.getElementById(targetId);
    if (!el) return;
    el.textContent = message;
    el.style.display = message ? 'block' : 'none';
}

async function submitSettingsPasswordChange() {
    if (!appUser) return;
    const currentEl = document.getElementById('settingsCurrentPassword');
    const nextEl = document.getElementById('settingsNewPassword');
    const confirmEl = document.getElementById('settingsConfirmPassword');
    if (!currentEl || !nextEl || !confirmEl) return;
    const current = (currentEl.value || '').trim();
    const next = (nextEl.value || '').trim();
    const confirm = (confirmEl.value || '').trim();
    const accounts = getUserAccounts();
    const key = normalizeJfaName(appUser);
    const account = accounts[key];
    if (!account) {
        setSettingsError('settingsAccountError', 'Account not found.');
        return;
    }
    const valid = await verifyAndMigrateAccountPassword(account, current, accounts, key);
    if (!valid) {
        setSettingsError('settingsAccountError', 'Current password is incorrect.');
        return;
    }
    const validation = validateStrongPassword(next);
    if (!validation.ok) {
        setSettingsError('settingsAccountError', validation.message);
        return;
    }
    if (next !== confirm) {
        setSettingsError('settingsAccountError', 'New password confirmation does not match.');
        return;
    }
    const record = await createPasswordRecord(next);
    account.passwordHash = record.hash;
    account.passwordSalt = record.salt;
    if (key === 'admin') {
        account.adminDefaultLocked = true;
        localStorage.removeItem(STORAGE_KEYS.adminPassword);
    }
    delete account.password;
    account.mustChangePassword = false;
    account.updatedAt = new Date().toISOString();
    accounts[key] = account;
    saveUserAccounts(accounts);
    currentEl.value = '';
    nextEl.value = '';
    confirmEl.value = '';
    setSettingsError('settingsAccountError', '');
    closeSettingsPasswordAssist(false);
    logUserMgmtAction('Password changed', `Account: ${formatJfaName(appUser)}`);
    showToast('Password changed successfully.', 'success');
    renderSettingsAuditSection();
}

function installBrandAssetFallbacks() {
    if (document.body?.dataset?.brandFallbackBound === '1') return;
    if (document.body) {
        document.body.dataset.brandFallbackBound = '1';
    }
    const candidates = ['matla-life-logo2.png', 'new-matla-logo.png', 'matla-life-logo.png', 'matla-logo.png'];
    document.addEventListener('error', (event) => {
        const target = event.target;
        if (!(target instanceof HTMLImageElement)) return;
        const current = String(target.getAttribute('src') || '').trim();
        const tried = new Set(
            String(target.dataset.logoFallbackTried || '')
                .split('|')
                .map((item) => item.trim())
                .filter(Boolean)
        );
        tried.add(current);
        const next = candidates.find((src) => !tried.has(src));
        target.dataset.logoFallbackTried = [...tried].join('|');
        if (!next) return;
        target.src = next;
    }, true);
}

function migrateUsernameReferences(oldUsername, newUsername) {
    const oldKey = normalizeJfaName(oldUsername);
    const newKey = normalizeJfaName(newUsername);
    if (!oldKey || !newKey) return;

    if (currentJFA?.name && normalizeJfaName(currentJFA.name) === oldKey) {
        currentJFA.name = newUsername;
        saveCurrentJfa();
    }

    const profile = jfaProfiles[oldKey] || jfaProfiles[newKey] || ensureJfaProfile(oldUsername) || {};
    profile.fullName = newUsername;
    profile.username = newKey;
    if (oldKey !== newKey) delete jfaProfiles[oldKey];
    jfaProfiles[newKey] = profile;
    saveJfaProfiles();

    let recordsChanged = false;
    jfaRecords.forEach((record) => {
        if (normalizeJfaName(record?.name) !== oldKey) return;
        record.name = newUsername;
        recordsChanged = true;
    });
    if (recordsChanged) {
        scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    }

    let leadsChanged = false;
    leadRecords.forEach((lead) => {
        if (normalizeJfaName(lead?.jfaName) !== oldKey) return;
        lead.jfaName = newUsername;
        leadsChanged = true;
    });
    if (leadsChanged) {
        scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    }

    let appointmentsChanged = false;
    appointmentRecords.forEach((appointment) => {
        if (normalizeJfaName(appointment?.jfaName) !== oldKey) return;
        appointment.jfaName = newUsername;
        appointmentsChanged = true;
    });
    if (appointmentsChanged) {
        scheduleStorageWrite(STORAGE_KEYS.appointments, JSON.stringify(appointmentRecords));
    }

    const weekly = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedback) || 'null');
    if (weekly?.entries && Array.isArray(weekly.entries)) {
        let changed = false;
        weekly.entries.forEach((entry) => {
            if (normalizeJfaName(entry?.name) !== oldKey) return;
            entry.name = newUsername;
            changed = true;
        });
        if (changed) {
            scheduleStorageWrite(STORAGE_KEYS.weeklyFeedback, JSON.stringify(weekly));
        }
    }

    const weeklyArchive = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedbackArchive) || '[]');
    if (Array.isArray(weeklyArchive)) {
        let changed = false;
        weeklyArchive.forEach((bucket) => {
            (bucket?.entries || []).forEach((entry) => {
                if (normalizeJfaName(entry?.name) !== oldKey) return;
                entry.name = newUsername;
                changed = true;
            });
        });
        if (changed) {
            scheduleStorageWrite(STORAGE_KEYS.weeklyFeedbackArchive, JSON.stringify(weeklyArchive));
        }
    }

    const archives = getArchives();
    if (Array.isArray(archives)) {
        let changed = false;
        archives.forEach((archive) => {
            (archive?.records || []).forEach((record) => {
                if (normalizeJfaName(record?.name) !== oldKey) return;
                record.name = newUsername;
                changed = true;
            });
        });
        if (changed) {
            scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(archives));
        }
    }

    if (oldKey !== newKey) {
        const oldEntries = Array.isArray(interventionLog[oldKey]) ? interventionLog[oldKey] : [];
        const existingNew = Array.isArray(interventionLog[newKey]) ? interventionLog[newKey] : [];
        if (oldEntries.length || existingNew.length) {
            interventionLog[newKey] = [...oldEntries, ...existingNew];
            delete interventionLog[oldKey];
            saveInterventionLog();
        }
    }

    saveLastJfaIdentity(newUsername, profile.team || '');
}

async function submitSettingsUsernameChange() {
    if (!appUser) return;
    const nextEl = document.getElementById('settingsNewUsernameSelf');
    const passwordEl = document.getElementById('settingsUsernamePassword');
    if (!nextEl || !passwordEl) return;
    const nextUsername = formatJfaName(nextEl.value || '');
    const currentPassword = (passwordEl.value || '').trim();
    const oldUsername = formatJfaName(appUser || '');
    const oldKey = normalizeJfaName(oldUsername);
    const nextKey = normalizeJfaName(nextUsername);
    if (!nextUsername) {
        setSettingsError('settingsAccountError', 'Enter a new username.');
        return;
    }
    if (!currentPassword) {
        setSettingsError('settingsAccountError', 'Enter your current password to confirm username change.');
        return;
    }
    if (!oldKey) {
        setSettingsError('settingsAccountError', 'Current account could not be resolved.');
        return;
    }
    if (nextKey === oldKey) {
        setSettingsError('settingsAccountError', 'New username must be different from current username.');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[oldKey];
    if (!account) {
        setSettingsError('settingsAccountError', 'Account not found.');
        return;
    }
    const valid = await verifyAndMigrateAccountPassword(account, currentPassword, accounts, oldKey);
    if (!valid) {
        setSettingsError('settingsAccountError', 'Current password is incorrect.');
        return;
    }
    if (isUsernameUnavailable(nextUsername, accounts)) {
        setSettingsError('settingsAccountError', 'That username has been used before. Please use a different one.');
        return;
    }

    const targetKey = oldKey === 'admin' ? 'admin' : nextKey;
    if (oldKey !== targetKey) delete accounts[oldKey];
    account.username = nextUsername;
    if (oldKey === 'admin') {
        account.adminDefaultLocked = true;
        localStorage.removeItem(STORAGE_KEYS.adminPassword);
    }
    account.updatedAt = new Date().toISOString();
    accounts[targetKey] = account;
    saveUserAccounts(accounts);
    markUsernameAsUsed(nextUsername);

    migrateUsernameReferences(oldUsername, nextUsername);
    appUser = nextUsername;
    sessionStorage.setItem(SESSION_KEYS.appUser, appUser);
    enforceLoggedUserContext();
    updateAppUserBadge();
    updatePermissionDrivenUi();
    updateSummary();
    updateStatistics();
    updateHeroSummary();
    renderAssignmentAppointmentReminders();

    nextEl.value = '';
    passwordEl.value = '';
    setSettingsError('settingsAccountError', '');
    logUserMgmtAction('Username changed', `Account: ${formatJfaName(oldUsername)} -> ${formatJfaName(nextUsername)}`);
    showToast('Username changed successfully.', 'success');
    renderSettingsPage();
    renderSettingsAuditSection();
}

async function createUserFromSettings() {
    if (!hasMasterAdminAccess()) {
        setSettingsError('settingsUserError', 'Only admin can create users.');
        return;
    }
    const usernameEl = document.getElementById('settingsNewUsername');
    const emailEl = document.getElementById('settingsNewEmail');
    const passwordEl = document.getElementById('settingsUserPassword');
    const confirmEl = document.getElementById('settingsUserPasswordConfirm');
    if (!usernameEl || !passwordEl || !confirmEl) return;
    const username = formatJfaName(usernameEl.value || '');
    const email = (emailEl?.value || '').trim().toLowerCase();
    const password = (passwordEl.value || '').trim();
    const confirm = (confirmEl.value || '').trim();
    const key = normalizeJfaName(username);
    if (!username) {
        setSettingsError('settingsUserError', 'Enter username.');
        return;
    }
    if (!email || !/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(email)) {
        setSettingsError('settingsUserError', 'Enter a valid email address.');
        return;
    }
    const validation = validateStrongPassword(password);
    if (!validation.ok) {
        setSettingsError('settingsUserError', validation.message);
        return;
    }
    if (password !== confirm) {
        setSettingsError('settingsUserError', 'Password confirmation does not match.');
        return;
    }
    const accounts = getUserAccounts();
    if (isUsernameUnavailable(username, accounts)) {
        setSettingsError('settingsUserError', 'That username has been used before. Please use a different one.');
        return;
    }
    const record = await createPasswordRecord(password);
    accounts[key] = {
        username,
        email,
        passwordHash: record.hash,
        passwordSalt: record.salt,
        createdAt: new Date().toISOString(),
        createdBy: formatJfaName(appUser || 'admin'),
        lastLoginAt: '',
        active: true,
        permissions: normalizeUserPermissions(getDefaultPermissions(false), false)
    };
    saveUserAccounts(accounts);
    markUsernameAsUsed(username);
    const profile = ensureJfaProfile(username) || {};
    profile.email = email;
    jfaProfiles[key] = profile;
    saveJfaProfiles();
    usernameEl.value = '';
    if (emailEl) emailEl.value = '';
    passwordEl.value = '';
    confirmEl.value = '';
    setSettingsError('settingsUserError', '');
    logUserMgmtAction('User created', `Account: ${username}`);
    showToast(`User ${username} created.`, 'success');
    renderSettingsPage();
}

async function createAdminOnlyAccountFromSettings() {
    if (!hasMasterAdminAccess()) {
        setSettingsError('settingsAdminAccountError', 'Only admin can create admin accounts.');
        return;
    }
    const usernameEl = document.getElementById('settingsAdminUsername');
    const emailEl = document.getElementById('settingsAdminEmail');
    const passwordEl = document.getElementById('settingsAdminPassword');
    const confirmEl = document.getElementById('settingsAdminPasswordConfirm');
    if (!usernameEl || !emailEl || !passwordEl || !confirmEl) return;
    const username = formatJfaName(usernameEl.value || '');
    const email = String(emailEl.value || '').trim().toLowerCase();
    const password = String(passwordEl.value || '').trim();
    const confirm = String(confirmEl.value || '').trim();
    const key = normalizeJfaName(username);
    if (!username) {
        setSettingsError('settingsAdminAccountError', 'Enter admin username.');
        return;
    }
    if (!email || !isValidEmail(email)) {
        setSettingsError('settingsAdminAccountError', 'Enter a valid admin email address.');
        return;
    }
    const validation = validateStrongPassword(password);
    if (!validation.ok) {
        setSettingsError('settingsAdminAccountError', validation.message);
        return;
    }
    if (password !== confirm) {
        setSettingsError('settingsAdminAccountError', 'Password confirmation does not match.');
        return;
    }
    if (key === 'admin') {
        setSettingsError('settingsAdminAccountError', 'Reserved username. Choose a different admin username.');
        return;
    }
    const accounts = getUserAccounts();
    if (isUsernameUnavailable(username, accounts)) {
        setSettingsError('settingsAdminAccountError', 'That username has been used before. Please choose a different one.');
        return;
    }
    const emailTaken = Object.values(accounts).some((account) => String(account?.email || '').toLowerCase() === email);
    if (emailTaken) {
        setSettingsError('settingsAdminAccountError', 'That email is already in use.');
        return;
    }
    const record = await createPasswordRecord(password);
    accounts[key] = {
        username,
        email,
        passwordHash: record.hash,
        passwordSalt: record.salt,
        createdAt: new Date().toISOString(),
        createdBy: formatJfaName(appUser || 'admin'),
        lastLoginAt: '',
        active: true,
        adminOnly: true,
        permissions: normalizeUserPermissions({ admin: true, learning: true, forms: true, leads: true, settings: true }, false)
    };
    saveUserAccounts(accounts);
    markUsernameAsUsed(username);
    usernameEl.value = '';
    emailEl.value = '';
    passwordEl.value = '';
    confirmEl.value = '';
    setSettingsError('settingsAdminAccountError', '');
    logUserMgmtAction('Admin account created', `Admin-only account: ${username}`);
    showToast(`Admin account ${username} created. Use Login as Admin only.`, 'success');
    renderSettingsPage();
}

async function resetSettingsUserPassword(encodedUsername) {
    if (!hasAdminUserSettingsAccess()) {
        setSettingsError('settingsUserError', 'Only admin can reset passwords.');
        return;
    }
    const username = decodeURIComponent(encodedUsername || '');
    const key = normalizeJfaName(username);
    if (!key || key === 'admin') {
        setSettingsError('settingsUserError', 'Use Account Security to change admin password.');
        return;
    }
    const input = prompt(`Reset ${formatJfaName(username)} password? Type RESET to confirm.`);
    if (input !== 'RESET') {
        showToast('Reset cancelled.', 'error');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        setSettingsError('settingsUserError', 'User not found.');
        return;
    }
    const resetDefault = generateStrongTemporaryPassword();
    const record = await createPasswordRecord(resetDefault);
    account.passwordHash = record.hash;
    account.passwordSalt = record.salt;
    delete account.password;
    account.mustChangePassword = true;
    account.updatedAt = new Date().toISOString();
    account.updatedBy = formatJfaName(appUser || 'admin');
    account.active = true;
    accounts[key] = account;
    saveUserAccounts(accounts);
    setSettingsError('settingsUserError', '');
    logUserMgmtAction('Password reset', `Account: ${formatJfaName(username)} (temporary password issued)`);
    showToast(`${formatJfaName(username)} password reset to ${resetDefault}.`, 'success');
    renderSettingsPage();
}

function generateStrongTemporaryPassword() {
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghijkmnpqrstuvwxyz';
    const digits = '23456789';
    const symbols = '!@#$%&*?';
    const all = `${upper}${lower}${digits}${symbols}`;
    const rand = (set) => set[Math.floor(Math.random() * set.length)];
    const chars = [rand(upper), rand(lower), rand(digits), rand(symbols)];
    while (chars.length < 12) chars.push(rand(all));
    for (let i = chars.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

function toggleSettingsUserState(encodedUsername) {
    if (!hasAdminUserSettingsAccess()) {
        setSettingsError('settingsUserError', 'Only admin can manage users.');
        return;
    }
    const username = decodeURIComponent(encodedUsername || '');
    const key = normalizeJfaName(username);
    if (!key || key === 'admin') {
        setSettingsError('settingsUserError', 'Admin account cannot be disabled.');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        setSettingsError('settingsUserError', 'User not found.');
        return;
    }
    const nextActive = account.active === false;
    account.active = nextActive;
    account.updatedAt = new Date().toISOString();
    account.updatedBy = formatJfaName(appUser || 'admin');
    accounts[key] = account;
    saveUserAccounts(accounts);
    setSettingsError('settingsUserError', '');
    logUserMgmtAction(nextActive ? 'User enabled' : 'User disabled', `Account: ${formatJfaName(username)}`);
    showToast(`${formatJfaName(username)} ${nextActive ? 'enabled' : 'disabled'}.`, 'success');
    renderSettingsPage();
}

function deleteSettingsUser(encodedUsername) {
    if (!hasAdminUserSettingsAccess()) {
        setSettingsError('settingsUserError', 'Only admin can delete users.');
        return;
    }
    const username = decodeURIComponent(encodedUsername || '');
    const key = normalizeJfaName(username);
    if (!key || key === 'admin') {
        setSettingsError('settingsUserError', 'Admin account cannot be deleted.');
        return;
    }
    if (key === normalizeJfaName(appUser || '')) {
        setSettingsError('settingsUserError', 'Cannot delete currently logged in user.');
        return;
    }
    const input = prompt(`Type DELETE to remove ${formatJfaName(username)}.`);
    if (input !== 'DELETE') {
        showToast('Delete cancelled.', 'error');
        return;
    }
    const accounts = getUserAccounts();
    if (!accounts[key]) {
        setSettingsError('settingsUserError', 'User not found.');
        return;
    }
    delete accounts[key];
    saveUserAccounts(accounts);
    setSettingsError('settingsUserError', '');
    logUserMgmtAction('User deleted', `Account: ${formatJfaName(username)}`);
    showToast(`${formatJfaName(username)} deleted.`, 'success');
    renderSettingsPage();
}

function lockAppToAuth() {
    const gate = document.getElementById('app-auth-gate');
    if (!gate) return;
    document.body.classList.add('app-locked');
    gate.classList.add('is-open');
    gate.setAttribute('aria-hidden', 'false');
    const userInput = document.getElementById('authUsername');
    if (userInput) {
        userInput.value = '';
        setTimeout(() => userInput.focus(), 60);
    }
    const passInput = document.getElementById('authPassword');
    const confirmInput = document.getElementById('authConfirmPassword');
    if (passInput) passInput.value = '';
    if (confirmInput) confirmInput.value = '';
    updateMobileBottomNavState(document.querySelector('.page.active')?.id || '');
}

function unlockAppFromAuth() {
    const gate = document.getElementById('app-auth-gate');
    if (!gate) return;
    gate.classList.remove('is-open');
    gate.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('app-locked');
    updateMobileBottomNavState(document.querySelector('.page.active')?.id || '');
}

function enforceLoggedUserContext() {
    if (!appUser) return;
    const key = normalizeJfaName(appUser);
    if (currentJFA?.name && normalizeJfaName(currentJFA.name) !== key) {
        currentJFA = null;
        localStorage.removeItem(STORAGE_KEYS.currentJfa);
    }
    const profile = jfaProfiles[key] || ensureJfaProfile(appUser) || {};
    saveLastJfaIdentity(appUser, profile.team || '');
}

async function tryRemoteSessionLogin(identifier, password) {
    if (!isRemoteSyncAllowed()) return { ok: false, skipped: true };
    try {
        const localSessionId = (sessionStorage.getItem(SESSION_KEYS.remoteSessionId) || '').trim();
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(REMOTE_API_TOKEN ? { Authorization: `Bearer ${REMOTE_API_TOKEN}` } : {})
            },
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                identifier,
                password,
                sessionId: localSessionId || `sess-${Date.now()}-${Math.floor(Math.random() * 100000)}`
            })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            return { ok: false, status: response.status, error: String(data?.error || 'Login failed') };
        }
        const account = data?.account && typeof data.account === 'object' ? data.account : {};
        const username = formatAuthIdentifier(account.username || identifier);
        const role = String(data?.role || 'PERSONAL').toUpperCase();
        const key = normalizeJfaName(username);
        const accounts = getUserAccounts();
        const existing = accounts[key] || {};
        accounts[key] = {
            ...existing,
            username,
            email: String(account.email || existing.email || '').trim().toLowerCase(),
            team: String(account.team || existing.team || '').trim(),
            active: existing.active !== false,
            adminOnly: account.adminOnly === true || role === 'ADMIN',
            permissions: normalizeUserPermissions(
                role === 'ADMIN'
                    ? { admin: true, learning: true, forms: true, leads: true, settings: true }
                    : role === 'TEAM'
                        ? { admin: true, learning: true, forms: true, leads: true, settings: true }
                        : getDefaultPermissions(false),
                role === 'ADMIN'
            ),
            lastLoginAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            remoteManaged: true
        };
        saveUserAccounts(accounts);
        setRemoteAuthState({
            accessToken: data?.accessToken || '',
            refreshToken: data?.refreshToken || '',
            sessionId: data?.sessionId || '',
            expiresIn: Number(data?.expiresIn || 0),
            refreshExpiresIn: Number(data?.refreshExpiresIn || 0)
        });
        remoteSyncReady = true;
        await refreshRemoteState();
        return { ok: true, username, role, account: accounts[key] };
    } catch (_) {
        return { ok: false, skipped: true };
    }
}

async function tryRemoteSessionRegister({ username, email, password, team = '' }) {
    if (!isRemoteSyncAllowed()) return { ok: false, skipped: true };
    try {
        const localSessionId = (sessionStorage.getItem(SESSION_KEYS.remoteSessionId) || '').trim();
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(REMOTE_API_TOKEN ? { Authorization: `Bearer ${REMOTE_API_TOKEN}` } : {})
            },
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                username,
                email,
                password,
                team,
                sessionId: localSessionId || `sess-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
                termsAcceptedAt: new Date().toISOString()
            })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            return { ok: false, status: response.status, error: String(data?.error || 'Registration failed') };
        }
        const account = data?.account && typeof data.account === 'object' ? data.account : {};
        const resolvedUsername = formatAuthIdentifier(account.username || username);
        const role = String(data?.role || 'PERSONAL').toUpperCase();
        const key = normalizeJfaName(resolvedUsername);
        const accounts = getUserAccounts();
        const existing = accounts[key] || {};
        accounts[key] = {
            ...existing,
            username: resolvedUsername,
            email: String(account.email || email || existing.email || '').trim().toLowerCase(),
            team: String(account.team || team || existing.team || '').trim(),
            active: true,
            adminOnly: false,
            permissions: normalizeUserPermissions(getDefaultPermissions(false), false),
            lastLoginAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            remoteManaged: true
        };
        saveUserAccounts(accounts);
        setRemoteAuthState({
            accessToken: data?.accessToken || '',
            refreshToken: data?.refreshToken || '',
            sessionId: data?.sessionId || '',
            expiresIn: Number(data?.expiresIn || 0),
            refreshExpiresIn: Number(data?.refreshExpiresIn || 0)
        });
        remoteSyncReady = true;
        await refreshRemoteState();
        return { ok: true, username: resolvedUsername, role, account: accounts[key] };
    } catch (_) {
        return { ok: false, skipped: true };
    }
}

async function syncAuthSessionHeartbeat() {
    if (!isRemoteSyncAllowed()) return false;
    if (!(await refreshRemoteAccessTokenIfNeeded())) return false;
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/session?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) clearRemoteAuthState();
            return false;
        }
        return true;
    } catch (_) {
        return false;
    }
}

function completeAppLogin(usernameRaw) {
    const username = formatJfaName(usernameRaw || '');
    const key = normalizeJfaName(username);
    appUser = username;
    sessionStorage.setItem(SESSION_KEYS.appUser, appUser);
    adminRole = 'PERSONAL';
    adminTeam = '';
    persistAdminScope();
    sessionStorage.removeItem(SESSION_KEYS.adminAccess);
    sessionStorage.removeItem(SESSION_KEYS.adminMenuAccess);
    localStorage.removeItem(STORAGE_KEYS.currentJfa);
    currentJFA = null;
    const profile = jfaProfiles[key] || ensureJfaProfile(username) || {};
    const team = profile.team || '';
    saveLastJfaIdentity(username, team);
    enforceLoggedUserContext();
    updateAppUserBadge();
    updatePermissionDrivenUi();
    unlockAppFromAuth();
    closeMenuPage();
    updateSummary();
    updateStatistics();
    updateHeroSummary();
    updateMenuScopeChips('admin');
    goToPage('landing-page');
    showToast(`Welcome ${username}.`, 'success');
    resetInactivityTimer();
    dispatchMorningAppointmentReminder();
    dispatchOneHourAppointmentReminders();
    refreshNotificationBadge();
    showLoginNotifications();
    renderAssignmentAppointmentReminders();
    startCloudPresenceWatcher();
    const account = getUserAccounts()[key];
    if (account?.mustChangePassword === true) {
        openMenuPage('settings');
        openSettingsPasswordAssist();
        showToast('Security update required: change your temporary password now.', 'error');
    }
}

function completeAdminLogin(usernameRaw) {
    const username = formatJfaName(usernameRaw || '');
    const key = normalizeJfaName(username);
    appUser = username;
    sessionStorage.setItem(SESSION_KEYS.appUser, appUser);
    adminRole = 'ADMIN';
    adminTeam = '';
    persistAdminScope();
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    sessionStorage.setItem(SESSION_KEYS.adminMenuAccess, 'true');
    localStorage.removeItem(STORAGE_KEYS.currentJfa);
    currentJFA = null;
    const profile = jfaProfiles[key] || ensureJfaProfile(username) || {};
    saveLastJfaIdentity(username, profile.team || '');
    enforceLoggedUserContext();
    updateAppUserBadge();
    updatePermissionDrivenUi();
    unlockAppFromAuth();
    closeMenuPage();
    updateSummary();
    updateStatistics();
    updateHeroSummary();
    renderAdminStandalonePage();
    goToPage('admin-standalone-page');
    logAudit('Admin page login', `${username} logged into Admin page`);
    logUserMgmtAction('Admin login', `Admin page access by ${username}`);
    showToast(`Welcome ${username}.`, 'success');
    resetInactivityTimer();
    refreshNotificationBadge();
    showLoginNotifications();
    startCloudPresenceWatcher();
}

async function submitAppAuth() {
    const userEl = document.getElementById('authUsername');
    const passEl = document.getElementById('authPassword');
    if (!userEl || !passEl) return;
    const identifier = (userEl.value || '').trim();
    const username = formatAuthIdentifier(identifier);
    const password = (passEl.value || '').trim();
    const key = normalizeJfaName(username);
    if (!identifier) {
        setAuthUiError('Enter your username or email.');
        return;
    }
    if (!password) {
        setAuthUiError('Enter your password.');
        return;
    }
    const accounts = getUserAccounts();
    if (authMode === 'signup') {
        const confirmEl = document.getElementById('authConfirmPassword');
        const termsEl = document.getElementById('authTermsCheck');
        const emailEl = document.getElementById('authEmail');
        const confirm = (confirmEl?.value || '').trim();
        const email = (emailEl?.value || '').trim().toLowerCase();
        if (password !== confirm) {
            setAuthUiError('Password confirmation does not match.');
            return;
        }
        const validation = validateStrongPassword(password);
        if (!validation.ok) {
            setAuthUiError(validation.message);
            return;
        }
        if (!termsEl?.checked) {
            setAuthUiError('Please agree to the confidentiality terms.');
            return;
        }
        if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            setAuthUiError('Enter a valid email address.');
            return;
        }
        if (key === 'admin') {
            setAuthUiError('Admin account cannot be created here.');
            return;
        }
        if (isUsernameUnavailable(username, accounts)) {
            setAuthUiError('That username has been used before. Please try a different one.');
            return;
        }
        const remoteSignup = await tryRemoteSessionRegister({
            username,
            email,
            password,
            team: ''
        });
        if (remoteSignup.ok) {
            localStorage.setItem('lastAuthUser', remoteSignup.username);
            persistAuthRememberState();
            completeAppLogin(remoteSignup.username);
            return;
        }
        if (isCloudSyncRequired()) {
            const message = remoteSignup.error
                ? `Cloud signup failed: ${remoteSignup.error}`
                : 'Cloud signup is unavailable right now. Check server/API configuration.';
            setAuthUiError(message);
            return;
        }
        const record = await createPasswordRecord(password);
        accounts[key] = {
            username,
            email,
            passwordHash: record.hash,
            passwordSalt: record.salt,
            createdAt: new Date().toISOString(),
            createdBy: 'self-signup',
            termsAcceptedAt: new Date().toISOString(),
            termsVersion: TERMS_POLICY_VERSION,
            lastLoginAt: new Date().toISOString(),
            active: true,
            permissions: normalizeUserPermissions(getDefaultPermissions(false), false)
        };
        saveUserAccounts(accounts);
        markUsernameAsUsed(username);
        const profile = ensureJfaProfile(username) || {};
        profile.email = email;
        jfaProfiles[key] = profile;
        saveJfaProfiles();
        localStorage.setItem('lastAuthUser', username);
        persistAuthRememberState();
        logUserMgmtAction('User created', `Account: ${username} (self-signup)`);
        pushSystemNotification(
            'USER',
            '',
            'New User Registered',
            `${formatJfaName(username)} has just created an account.`,
            { userKey: 'admin' }
        );
        completeAppLogin(username);
        return;
    }

    const remoteLogin = await tryRemoteSessionLogin(identifier, password);
    if (remoteLogin.ok) {
        if (authMode === 'admin') {
            if (remoteLogin.role !== 'ADMIN') {
                setAuthUiError('Only Admin accounts can use "Login as Admin".');
                return;
            }
            completeAdminLogin(remoteLogin.username);
            return;
        }
        if (remoteLogin.account?.adminOnly === true || remoteLogin.role === 'ADMIN') {
            setAuthUiError('Admin account must use "Login as Admin" from the login page.');
            return;
        }
        completeAppLogin(remoteLogin.username);
        return;
    }
    const remoteError = (!remoteLogin.skipped && remoteLogin.error) ? String(remoteLogin.error) : '';
    if (isCloudSyncRequired() && authMode !== 'signup') {
        const message = remoteError || 'Cloud login is unavailable. Please verify backend/API is online.';
        setAuthUiError(message);
        return;
    }

    if (isRemoteSyncAllowed()) {
        await refreshRemoteState();
    }
    const localAccounts = getUserAccounts();
    const resolvedKey = resolveAccountKey(identifier);
    const failKey = `loginFail:${resolvedKey}`;
    const lockKey = `loginLock:${resolvedKey}`;
    const lockedUntil = Number(localStorage.getItem(lockKey) || 0);
    const isAdminLocalBypass = authMode === 'admin' && resolvedKey === 'admin';
    if (!isAdminLocalBypass && lockedUntil && Date.now() < lockedUntil) {
        const mins = Math.ceil((lockedUntil - Date.now()) / 60000);
        setAuthUiError(`Account locked. Try again in ${mins} minute(s).`);
        return;
    }
    const account = localAccounts[resolvedKey];
    if (!account || !(await verifyAndMigrateAccountPassword(account, password, localAccounts, resolvedKey))) {
        const fails = Number(localStorage.getItem(failKey) || 0) + 1;
        localStorage.setItem(failKey, String(fails));
        if (fails >= 5) {
            const until = Date.now() + 10 * 60 * 1000;
            localStorage.setItem(lockKey, String(until));
            localStorage.removeItem(failKey);
            setAuthUiError('Too many failed attempts. Account locked for 10 minutes.');
        } else {
            setAuthUiError(remoteError || 'Invalid username/email or password.');
        }
        passEl.select();
        return;
    }
    if (account.active === false) {
        setAuthUiError('This account is disabled. Please contact admin.');
        return;
    }
    if (authMode !== 'admin' && account.adminOnly === true) {
        setAuthUiError('This account is admin-only. Please use "Login as Admin".');
        return;
    }
    localStorage.removeItem(failKey);
    localStorage.removeItem(lockKey);
    const isAdminUser = resolvedKey === 'admin';
    account.permissions = normalizeUserPermissions(account.permissions, isAdminUser);
    account.active = account.active !== false;
    if (isAdminUser && authMode !== 'admin') {
        setAuthUiError('Admin account must use "Login as Admin" from the login page.');
        return;
    }
    if (authMode === 'admin') {
        const canAdminAccess = account.adminOnly === true || account.permissions?.admin === true || resolvedKey === 'admin';
        if (!canAdminAccess) {
            setAuthUiError('Admin access is restricted to Admin (All) accounts.');
            return;
        }
    }
    account.username = formatAuthIdentifier(account.username || username);
    account.lastLoginAt = new Date().toISOString();
    localAccounts[resolvedKey] = account;
    saveUserAccounts(localAccounts);
    localStorage.setItem('lastAuthUser', account.username || username);
    persistAuthRememberState();
    if (authMode === 'admin') {
        completeAdminLogin(account.username || username);
        return;
    }
    completeAppLogin(account.username || username);
}

function logoutAppUser() {
    stopCloudPresenceWatcher();
    if (inactivityTimer) {
        clearTimeout(inactivityTimer);
        inactivityTimer = null;
    }
    const remoteState = getRemoteAuthState();
    if (remoteState.accessToken && remoteState.sessionId && isRemoteSyncAllowed()) {
        fetch(`${REMOTE_API_BASE}/api/auth/logout`, {
            method: 'POST',
            headers: buildRemoteHeaders(),
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                sessionId: remoteState.sessionId
            })
        }).catch(() => {});
    }
    clearRemoteAuthState();
    remoteSyncReady = false;
    appUser = '';
    sessionStorage.removeItem(SESSION_KEYS.appUser);
    sessionStorage.removeItem(SESSION_KEYS.adminAccess);
    sessionStorage.removeItem(SESSION_KEYS.adminMenuAccess);
    adminRole = 'PERSONAL';
    adminTeam = '';
    persistAdminScope();
    currentJFA = null;
    localStorage.removeItem(STORAGE_KEYS.currentJfa);
    localStorage.removeItem(STORAGE_KEYS.lastJfaIdentity);
    updateAppUserBadge();
    updatePermissionDrivenUi();
    setAuthMode('signin');
    lockAppToAuth();
}

function confirmSidebarSignOut() {
    openSignOutConfirmModal();
}

function openPolicyModal() {
    const modal = document.getElementById('policy-modal');
    if (!modal) return;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
}

function closePolicyModal() {
    const modal = document.getElementById('policy-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function openForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    const emailEl = document.getElementById('forgotPasswordEmail');
    if (!modal || !emailEl) return;
    emailEl.value = '';
    setModalError('', 'forgotPasswordError');
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => emailEl.focus(), 30);
    checkForgotPasswordConfigHint();
}

function closeForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    setModalError('', 'forgotPasswordError');
}

async function submitForgotPassword() {
    const emailEl = document.getElementById('forgotPasswordEmail');
    if (!emailEl) return;
    const email = (emailEl.value || '').trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        setModalError('Enter a valid email address.', 'forgotPasswordError');
        return;
    }
    if (!isRemoteSyncAllowed()) {
        setModalError('Password reset requires a secure server connection.', 'forgotPasswordError');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/request-reset`, {
            method: 'POST',
            headers: buildRemoteHeaders(),
            body: JSON.stringify({
                scope: REMOTE_STATE_SCOPE,
                email
            })
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            const message = data?.error || `Unable to send reset email right now (HTTP ${response.status}).`;
            throw new Error(message);
        }
        closeForgotPasswordModal();
        showToast('If the email exists, a reset link has been sent.', 'success');
    } catch (error) {
        const msg = String(error?.message || '');
        if (/not configured/i.test(msg)) {
            setModalError('Reset email is not configured on the server yet. Ask admin to set SMTP and APP_PUBLIC_URL.', 'forgotPasswordError');
            return;
        }
        if (/unauthorized|forbidden|token|401|403/i.test(msg)) {
            setModalError('Reset request was blocked by server auth. Check API token and CORS on the live server.', 'forgotPasswordError');
            return;
        }
        setModalError(msg || 'Unable to send reset email right now.', 'forgotPasswordError');
    }
}

function stopCloudPresenceWatcher() {
    if (cloudPresenceTimer) {
        clearInterval(cloudPresenceTimer);
        cloudPresenceTimer = null;
    }
}

function startCloudPresenceWatcher() {
    stopCloudPresenceWatcher();
    if (!isRemoteSyncAllowed()) return;
    cloudPresenceTimer = setInterval(async () => {
        if (!appUser || document.visibilityState !== 'visible') return;
        if (!navigator.onLine) return;
        const heartbeatOk = await syncAuthSessionHeartbeat();
        if (!heartbeatOk) {
            if (isCloudSyncRequired()) setSyncState('error');
            return;
        }
        await refreshRemoteState();
    }, 60000);
}

async function checkForgotPasswordConfigHint() {
    if (!isRemoteSyncAllowed()) return;
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/config`, {
            headers: buildRemoteHeaders()
        });
        if (!response.ok) return;
        const data = await response.json().catch(() => ({}));
        if (data?.resetEmailConfigured === false) {
            setModalError('Reset email is not configured on the server yet. Ask admin to set SMTP and APP_PUBLIC_URL.', 'forgotPasswordError');
        }
    } catch (_) {
        // Keep silent here; submit flow handles hard errors.
    }
}

function openResetPasswordModal(token, scope) {
    const modal = document.getElementById('reset-password-modal');
    const newEl = document.getElementById('resetPasswordNew');
    const confirmEl = document.getElementById('resetPasswordConfirm');
    if (!modal || !newEl || !confirmEl) return;
    pendingResetToken = token || '';
    pendingResetScope = scope || REMOTE_STATE_SCOPE;
    newEl.value = '';
    confirmEl.value = '';
    setModalError('', 'resetPasswordError');
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => newEl.focus(), 30);
}

function closeResetPasswordModal() {
    const modal = document.getElementById('reset-password-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    setModalError('', 'resetPasswordError');
    pendingResetToken = '';
    pendingResetScope = '';
}

async function submitResetPassword() {
    const newEl = document.getElementById('resetPasswordNew');
    const confirmEl = document.getElementById('resetPasswordConfirm');
    if (!newEl || !confirmEl) return;
    const next = (newEl.value || '').trim();
    const confirm = (confirmEl.value || '').trim();
    const validation = validateStrongPassword(next);
    if (!validation.ok) {
        setModalError(validation.message, 'resetPasswordError');
        return;
    }
    if (next !== confirm) {
        setModalError('Password confirmation does not match.', 'resetPasswordError');
        return;
    }
    if (!pendingResetToken) {
        setModalError('Reset token missing. Request a new reset link.', 'resetPasswordError');
        return;
    }
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/auth/reset`, {
            method: 'POST',
            headers: buildRemoteHeaders(),
            body: JSON.stringify({
                scope: pendingResetScope || REMOTE_STATE_SCOPE,
                token: pendingResetToken,
                newPassword: next
            })
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data?.error || 'Failed');
        }
        closeResetPasswordModal();
        await refreshRemoteState();
        showToast('Password updated. You can sign in now.', 'success');
        if (window.location.hash.includes('#reset')) {
            history.replaceState(null, '', window.location.pathname + window.location.search);
        }
    } catch (error) {
        const msg = String(error?.message || '').trim();
        if (msg) {
            setModalError(msg, 'resetPasswordError');
            return;
        }
        setModalError('Unable to reset password. The link may be expired.', 'resetPasswordError');
    }
}

function parseResetLink() {
    const hash = window.location.hash || '';
    if (!hash.startsWith('#reset')) return;
    const query = hash.includes('?') ? hash.split('?')[1] : '';
    const params = new URLSearchParams(query);
    const token = params.get('token') || '';
    const scope = params.get('scope') || REMOTE_STATE_SCOPE;
    if (token) {
        if (!document.body.classList.contains('app-locked')) {
            logoutAppUser();
        } else {
            lockAppToAuth();
        }
        openResetPasswordModal(token, scope);
    }
}

async function refreshRemoteState() {
    if (!isRemoteSyncAllowed()) return;
    if (!(await refreshRemoteAccessTokenIfNeeded())) return;
    try {
        const response = await fetch(`${REMOTE_API_BASE}/api/state/load?scope=${encodeURIComponent(REMOTE_STATE_SCOPE)}`, {
            headers: buildRemoteHeaders()
        });
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) clearRemoteAuthState();
            throw new Error('load failed');
        }
        const data = await response.json();
        const remotePayload = data?.payload && typeof data.payload === 'object' ? data.payload : null;
        if (remotePayload) {
            applyRemoteStatePayload(remotePayload);
            localStorage.setItem(STORAGE_KEYS.remoteSyncAt, data.updatedAt || new Date().toISOString());
        }
    } catch (_) {
        // ignore
    }
}

function openAppConfirmModal(options = {}) {
    const modal = document.getElementById('app-confirm-modal');
    const titleEl = document.getElementById('appConfirmTitle');
    const bodyEl = document.getElementById('appConfirmMessage');
    const cancelBtn = document.getElementById('appConfirmCancelBtn');
    const okBtn = document.getElementById('appConfirmOkBtn');
    if (!modal || !titleEl || !bodyEl || !cancelBtn || !okBtn) {
        return Promise.resolve(false);
    }
    const title = String(options.title || 'Confirm Action');
    const message = String(options.message || 'Are you sure?');
    const confirmText = String(options.confirmText || 'Confirm');
    const cancelText = String(options.cancelText || 'Cancel');
    titleEl.textContent = title;
    bodyEl.textContent = message;
    okBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    if (appConfirmResolver) {
        appConfirmResolver(false);
        appConfirmResolver = null;
    }
    return new Promise((resolve) => {
        appConfirmResolver = resolve;
        setTimeout(() => cancelBtn.focus(), 20);
    });
}

function closeAppConfirmModal(result = false) {
    const modal = document.getElementById('app-confirm-modal');
    if (modal) {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
    }
    if (appConfirmResolver) {
        const resolver = appConfirmResolver;
        appConfirmResolver = null;
        resolver(Boolean(result));
    }
}

function openSignOutConfirmModal() {
    const modal = document.getElementById('signout-confirm-modal');
    if (!modal) return;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    const cancelBtn = modal.querySelector('[data-signout-cancel]');
    if (cancelBtn) {
        setTimeout(() => cancelBtn.focus(), 30);
    }
}

function closeSignOutConfirmModal() {
    const modal = document.getElementById('signout-confirm-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function confirmSignOutNow() {
    closeSignOutConfirmModal();
    toggleSidebar(true);
    logoutAppUser();
}

function persistAdminScope() {
    sessionStorage.setItem(SESSION_KEYS.adminRole, adminRole);
    sessionStorage.setItem(SESSION_KEYS.adminTeam, adminTeam);
}

function getAdminUsername() {
    const accounts = getUserAccounts();
    const admin = accounts.admin || {};
    return formatAuthIdentifier(admin.username || DEFAULT_ADMIN_USERNAME) || DEFAULT_ADMIN_USERNAME;
}

function getAdminPasswordRecord() {
    const stored = (localStorage.getItem(STORAGE_KEYS.adminPassword) || '').trim();
    if (!stored) return null;
    try {
        const parsed = JSON.parse(stored);
        if (parsed && typeof parsed === 'object' && parsed.hash && parsed.salt) return parsed;
    } catch (_) {
        return { legacy: stored };
    }
    return { legacy: stored };
}

async function setAdminPassword(nextPassword) {
    const value = String(nextPassword || '').trim();
    if (!value) return false;
    const validation = validateStrongPassword(value);
    if (!validation.ok) return false;
    const record = await createPasswordRecord(value);
    scheduleStorageWrite(STORAGE_KEYS.adminPassword, JSON.stringify(record));
    return true;
}

async function verifyAdminPassword(inputPassword) {
    const password = String(inputPassword || '').trim();
    const accounts = getUserAccounts();
    const admin = accounts.admin || {};
    if (admin.passwordHash && admin.passwordSalt) {
        return verifyPasswordRecord(password, { salt: admin.passwordSalt, hash: admin.passwordHash });
    }
    if (String(admin.password || '') === password) {
        const record = await createPasswordRecord(password);
        admin.passwordHash = record.hash;
        admin.passwordSalt = record.salt;
        delete admin.password;
        accounts.admin = admin;
        saveUserAccounts(accounts);
        return true;
    }
    const stored = getAdminPasswordRecord();
    if (stored && stored.hash && stored.salt) {
        return verifyPasswordRecord(password, stored);
    }
    if (stored && stored.legacy) {
        if (password !== stored.legacy) return false;
        await setAdminPassword(password);
        return true;
    }
    const expected = ADMIN_PIN || DEFAULT_ADMIN_PASSWORD;
    if (password !== expected) return false;
    if (!ADMIN_PIN) {
        await setAdminPassword(password);
    }
    return true;
}

function setModalError(message = '', errorId = 'adminAuthError') {
    const errorEl = document.getElementById(errorId);
    if (!errorEl) return;
    errorEl.textContent = message;
    errorEl.style.display = message ? 'block' : 'none';
}

function openAdminAuthModal(onSuccess = null, triggerEvent = null) {
    const modal = document.getElementById('admin-auth-modal');
    const username = document.getElementById('adminAuthUsername');
    const password = document.getElementById('adminAuthPassword');
    const card = modal ? modal.querySelector('.modal-card') : null;
    if (!modal || !username || !password || !card) return;
    pendingAdminAccessAction = typeof onSuccess === 'function' ? onSuccess : null;
    username.value = getAdminUsername();
    password.value = '';
    setModalError('', 'adminAuthError');
    modal.classList.remove('is-contextual');
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.margin = '';
    if (triggerEvent && typeof triggerEvent.clientX === 'number' && typeof triggerEvent.clientY === 'number') {
        const width = Math.min(440, Math.floor(window.innerWidth * 0.92));
        const height = Math.min(360, Math.floor(window.innerHeight * 0.85));
        const gap = 14;
        const left = Math.max(12, Math.min(Math.round(triggerEvent.clientX - width / 2), window.innerWidth - width - 12));
        const top = Math.max(12, Math.min(Math.round(triggerEvent.clientY + gap), window.innerHeight - height - 12));
        modal.classList.add('is-contextual');
        card.style.position = 'fixed';
        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
        card.style.margin = '0';
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => password.focus(), 30);
}

function closeAdminAuthModal() {
    const modal = document.getElementById('admin-auth-modal');
    if (!modal) return;
    const card = modal.querySelector('.modal-card');
    modal.classList.remove('is-open');
    modal.classList.remove('is-contextual');
    modal.setAttribute('aria-hidden', 'true');
    if (card) {
        card.style.position = '';
        card.style.left = '';
        card.style.top = '';
        card.style.margin = '';
    }
    setModalError('', 'adminAuthError');
}

function openAdminMenuAuthModal(onSuccess = null, triggerEvent = null) {
    const modal = document.getElementById('admin-menu-auth-modal');
    const username = document.getElementById('adminMenuAuthUsername');
    const password = document.getElementById('adminMenuAuthPassword');
    const card = modal ? modal.querySelector('.modal-card') : null;
    if (!modal || !username || !password || !card) return;
    pendingAdminMenuAccessAction = typeof onSuccess === 'function' ? onSuccess : null;
    username.value = '';
    password.value = '';
    setModalError('', 'adminMenuAuthError');
    modal.classList.remove('is-contextual');
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.margin = '';
    if (triggerEvent && typeof triggerEvent.clientX === 'number' && typeof triggerEvent.clientY === 'number') {
        const width = Math.min(440, Math.floor(window.innerWidth * 0.92));
        const height = Math.min(360, Math.floor(window.innerHeight * 0.85));
        const gap = 14;
        const left = Math.max(12, Math.min(Math.round(triggerEvent.clientX - width / 2), window.innerWidth - width - 12));
        const top = Math.max(12, Math.min(Math.round(triggerEvent.clientY + gap), window.innerHeight - height - 12));
        modal.classList.add('is-contextual');
        card.style.position = 'fixed';
        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
        card.style.margin = '0';
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => username.focus(), 30);
}

function closeAdminMenuAuthModal() {
    const modal = document.getElementById('admin-menu-auth-modal');
    if (!modal) return;
    const card = modal.querySelector('.modal-card');
    modal.classList.remove('is-open');
    modal.classList.remove('is-contextual');
    modal.setAttribute('aria-hidden', 'true');
    if (card) {
        card.style.position = '';
        card.style.left = '';
        card.style.top = '';
        card.style.margin = '';
    }
    setModalError('', 'adminMenuAuthError');
}

async function submitAdminMenuAccess() {
    const usernameEl = document.getElementById('adminMenuAuthUsername');
    const passwordEl = document.getElementById('adminMenuAuthPassword');
    if (!usernameEl || !passwordEl) return;
    const identifier = (usernameEl.value || '').trim();
    const password = (passwordEl.value || '').trim();
    if (!identifier) {
        setModalError('Enter username or email.', 'adminMenuAuthError');
        return;
    }
    if (!password) {
        setModalError('Enter password.', 'adminMenuAuthError');
        return;
    }
    const accounts = getUserAccounts();
    const key = resolveAccountKey(identifier);
    if (normalizeJfaName(appUser) && normalizeJfaName(appUser) !== key) {
        setModalError('Please sign in with your own team leader/admin account first.', 'adminMenuAuthError');
        return;
    }
    const account = accounts[key];
    if (!account || !(await verifyAndMigrateAccountPassword(account, password, accounts, key))) {
        setModalError('Invalid username/email or password.', 'adminMenuAuthError');
        return;
    }
    if (!canAccessAdminMenuForAccount(key, account)) {
        setModalError('Only team leaders or Admin can access this menu.', 'adminMenuAuthError');
        return;
    }
    sessionStorage.setItem(SESSION_KEYS.adminMenuAccess, 'true');
    logAudit('Admin menu access', `${formatJfaName(account.username || key)} authenticated`);
    showToast('Admin menu unlocked.', 'success');
    closeAdminMenuAuthModal();
    const action = pendingAdminMenuAccessAction;
    pendingAdminMenuAccessAction = null;
    if (typeof action === 'function') action();
}

async function submitAdminAccess() {
    const usernameEl = document.getElementById('adminAuthUsername');
    const passwordEl = document.getElementById('adminAuthPassword');
    if (!usernameEl || !passwordEl) return;
    const username = (usernameEl.value || '').trim();
    const password = (passwordEl.value || '').trim();
    if (!username) {
        setModalError('Enter username or email.', 'adminAuthError');
        return;
    }
    if (!password) {
        setModalError('Enter admin password.', 'adminAuthError');
        return;
    }
    if (username !== getAdminUsername() || !(await verifyAdminPassword(password))) {
        setModalError('Invalid username/email or password.', 'adminAuthError');
        passwordEl.select();
        return;
    }
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    closeAdminAuthModal();
    const action = pendingAdminAccessAction;
    pendingAdminAccessAction = null;
    if (typeof action === 'function') action();
}

function openAdminPasswordModal() {
    const modal = document.getElementById('admin-password-modal');
    const current = document.getElementById('adminCurrentPassword');
    const next = document.getElementById('adminNewPassword');
    const confirm = document.getElementById('adminConfirmPassword');
    if (!modal || !current || !next || !confirm) return;
    current.value = '';
    next.value = '';
    confirm.value = '';
    setModalError('', 'adminPasswordError');
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => current.focus(), 30);
}

function closeAdminPasswordModal() {
    const modal = document.getElementById('admin-password-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    setModalError('', 'adminPasswordError');
}

function openAdminAllAccessModal(onSuccess = null, triggerEvent = null) {
    const modal = document.getElementById('admin-all-access-modal');
    const username = document.getElementById('adminAllUsername');
    const password = document.getElementById('adminAllPassword');
    const card = modal ? modal.querySelector('.modal-card') : null;
    if (!modal || !username || !password || !card) return;
    username.value = getAdminUsername();
    password.value = '';
    pendingAdminAllAccessAction = typeof onSuccess === 'function' ? onSuccess : null;
    modal.classList.remove('is-contextual');
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.margin = '';
    if (triggerEvent && typeof triggerEvent.clientX === 'number' && typeof triggerEvent.clientY === 'number') {
        const width = Math.min(440, Math.floor(window.innerWidth * 0.92));
        const height = Math.min(360, Math.floor(window.innerHeight * 0.85));
        const gap = 14;
        const left = Math.max(12, Math.min(Math.round(triggerEvent.clientX - width / 2), window.innerWidth - width - 12));
        const top = Math.max(12, Math.min(Math.round(triggerEvent.clientY + gap), window.innerHeight - height - 12));
        modal.classList.add('is-contextual');
        card.style.position = 'fixed';
        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
        card.style.margin = '0';
    }
    setModalError('', 'adminAllAccessError');
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => password.focus(), 30);
}

function closeAdminAllAccessModal() {
    const modal = document.getElementById('admin-all-access-modal');
    if (!modal) return;
    const card = modal.querySelector('.modal-card');
    modal.classList.remove('is-open');
    modal.classList.remove('is-contextual');
    modal.setAttribute('aria-hidden', 'true');
    if (card) {
        card.style.position = '';
        card.style.left = '';
        card.style.top = '';
        card.style.margin = '';
    }
    setModalError('', 'adminAllAccessError');
}

function openAdminAllAccessInline() {
    const panel = document.getElementById('adminAllInlineGate');
    const username = document.getElementById('adminAllInlineUsername');
    const password = document.getElementById('adminAllInlinePassword');
    if (!panel || !username || !password) return;
    panel.style.display = 'block';
    username.value = getAdminUsername();
    password.value = '';
    setModalError('', 'adminAllInlineError');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setTimeout(() => password.focus(), 50);
}

function closeAdminAllAccessInline() {
    const panel = document.getElementById('adminAllInlineGate');
    if (!panel) return;
    panel.style.display = 'none';
    setModalError('', 'adminAllInlineError');
}

function openTeamAuthInline(teamName) {
    const panel = document.getElementById('teamInlineGate');
    const username = document.getElementById('teamInlineUsername');
    const password = document.getElementById('teamInlinePassword');
    const title = document.getElementById('teamInlineTitle');
    if (!panel || !username || !password) return;
    pendingTeamAccessTeam = teamName || '';
    if (title) {
        title.textContent = `${teamName || 'Team'} Portal Access`;
    }
    panel.style.display = 'block';
    username.value = '';
    password.value = '';
    setModalError('', 'teamInlineError');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setTimeout(() => username.focus(), 50);
}

function closeTeamAuthInline() {
    const panel = document.getElementById('teamInlineGate');
    if (!panel) return;
    panel.style.display = 'none';
    setModalError('', 'teamInlineError');
    pendingTeamAccessTeam = '';
}

async function submitTeamPortalAccessInline() {
    const usernameEl = document.getElementById('teamInlineUsername');
    const passwordEl = document.getElementById('teamInlinePassword');
    if (!usernameEl || !passwordEl) return;
    const identifier = (usernameEl.value || '').trim();
    const username = formatAuthIdentifier(identifier);
    const password = (passwordEl.value || '').trim();
    if (!identifier) {
        setModalError('Enter username or email.', 'teamInlineError');
        return;
    }
    if (!password) {
        setModalError('Enter password.', 'teamInlineError');
        return;
    }
    const teamName = pendingTeamAccessTeam || '';
    if (!teamName) {
        setModalError('Team portal not set.', 'teamInlineError');
        return;
    }
    const accounts = getUserAccounts();
    const key = resolveAccountKey(identifier) || normalizeJfaName(username);
    const account = accounts[key];
    if (!account || !(await verifyAndMigrateAccountPassword(account, password, accounts, key))) {
        setModalError('Invalid username/email or password.', 'teamInlineError');
        return;
    }
    if (account.active === false) {
        setModalError('This account is disabled.', 'teamInlineError');
        return;
    }
    const isAdminUser = key === 'admin';
    if (!isAdminUser) {
        const team = account.team || jfaProfiles[key]?.team || '';
        if (!team) {
            setModalError('Team not set for this account. Contact admin.', 'teamInlineError');
            return;
        }
        if (normalizeJfaName(team) !== normalizeJfaName(teamName)) {
            setModalError('You are not allowed to access this team portal.', 'teamInlineError');
            return;
        }
    }
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    closeTeamAuthInline();
    openTeamDetailPage(teamName, true);
}

function openTeamAuthModal(teamName, triggerEvent = null) {
    const modal = document.getElementById('team-auth-modal');
    const username = document.getElementById('teamAuthUsername');
    const password = document.getElementById('teamAuthPassword');
    const subtitle = document.getElementById('teamAuthSubtitle');
    const card = modal ? modal.querySelector('.modal-card') : null;
    if (!modal || !username || !password || !card) return;
    pendingTeamAccessTeam = teamName || '';
    if (subtitle) {
        subtitle.textContent = `Enter credentials to access ${teamName || 'Team'} portal.`;
    }
    username.value = '';
    password.value = '';
    setModalError('', 'teamAuthError');
    modal.classList.remove('is-contextual');
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.margin = '';
    if (triggerEvent && typeof triggerEvent.clientX === 'number' && typeof triggerEvent.clientY === 'number') {
        const width = Math.min(440, Math.floor(window.innerWidth * 0.92));
        const height = Math.min(360, Math.floor(window.innerHeight * 0.85));
        const gap = 14;
        const left = Math.max(12, Math.min(Math.round(triggerEvent.clientX - width / 2), window.innerWidth - width - 12));
        const top = Math.max(12, Math.min(Math.round(triggerEvent.clientY + gap), window.innerHeight - height - 12));
        modal.classList.add('is-contextual');
        card.style.position = 'fixed';
        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
        card.style.margin = '0';
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => username.focus(), 30);
}

function closeTeamAuthModal() {
    const modal = document.getElementById('team-auth-modal');
    if (!modal) return;
    const card = modal.querySelector('.modal-card');
    modal.classList.remove('is-open');
    modal.classList.remove('is-contextual');
    modal.setAttribute('aria-hidden', 'true');
    if (card) {
        card.style.position = '';
        card.style.left = '';
        card.style.top = '';
        card.style.margin = '';
    }
    setModalError('', 'teamAuthError');
    pendingTeamAccessTeam = '';
}

async function submitTeamPortalAccess() {
    const usernameEl = document.getElementById('teamAuthUsername');
    const passwordEl = document.getElementById('teamAuthPassword');
    if (!usernameEl || !passwordEl) return;
    const identifier = (usernameEl.value || '').trim();
    const username = formatAuthIdentifier(identifier);
    const password = (passwordEl.value || '').trim();
    if (!identifier) {
        setModalError('Enter username or email.', 'teamAuthError');
        return;
    }
    if (!password) {
        setModalError('Enter password.', 'teamAuthError');
        return;
    }
    const teamName = pendingTeamAccessTeam || '';
    if (!teamName) {
        setModalError('Team portal not set.', 'teamAuthError');
        return;
    }
    const accounts = getUserAccounts();
    const key = resolveAccountKey(identifier) || normalizeJfaName(username);
    const account = accounts[key];
    if (!account || !(await verifyAndMigrateAccountPassword(account, password, accounts, key))) {
        setModalError('Invalid username/email or password.', 'teamAuthError');
        return;
    }
    if (account.active === false) {
        setModalError('This account is disabled.', 'teamAuthError');
        return;
    }
    const isAdminUser = key === 'admin';
    if (!isAdminUser) {
        const team = account.team || jfaProfiles[key]?.team || '';
        if (!team) {
            setModalError('Team not set for this account. Contact admin.', 'teamAuthError');
            return;
        }
        if (normalizeJfaName(team) !== normalizeJfaName(teamName)) {
            setModalError('You are not allowed to access this team portal.', 'teamAuthError');
            return;
        }
    }
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    closeTeamAuthModal();
    openTeamDetailPage(teamName, true);
}

async function submitAdminAllAccessInline() {
    const usernameEl = document.getElementById('adminAllInlineUsername');
    const passwordEl = document.getElementById('adminAllInlinePassword');
    if (!usernameEl || !passwordEl) return;
    const username = (usernameEl.value || '').trim();
    const password = (passwordEl.value || '').trim();
    if (!username) {
        setModalError('Enter username or email.', 'adminAllInlineError');
        return;
    }
    if (!password) {
        setModalError('Enter admin password.', 'adminAllInlineError');
        return;
    }
    if (username !== getAdminUsername() || !(await verifyAdminPassword(password))) {
        setModalError('Invalid username/email or password.', 'adminAllInlineError');
        passwordEl.select();
        return;
    }
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    await logAdminAllAccess(username);
    logAudit('Admin (All) access', `${username} opened Admin (All)`);
    closeAdminAllAccessInline();
    openTeamDetailPage('ALL', true);
}

async function logAdminAllAccess(username) {
    const payload = {
        scope: REMOTE_STATE_SCOPE,
        username: String(username || '').trim(),
        section: 'Admin (All)',
        role: adminRole || 'PERSONAL',
        source: 'web',
        userAgent: navigator.userAgent || '',
        happenedAt: new Date().toISOString()
    };
    let remoteSaved = false;
    if (isRemoteSyncAllowed()) {
        try {
            const response = await fetch(`${REMOTE_API_BASE}/api/admin/access-log`, {
                method: 'POST',
                headers: buildRemoteHeaders(),
                body: JSON.stringify(payload)
            });
            remoteSaved = response.ok;
        } catch (_) {
            remoteSaved = false;
        }
    }
    if (!remoteSaved) {
        const local = JSON.parse(localStorage.getItem('adminAllAccessLog') || '[]');
        local.unshift(payload);
        scheduleStorageWrite('adminAllAccessLog', JSON.stringify(local.slice(0, 200)));
    }
}

async function submitAdminAllAccess() {
    const usernameEl = document.getElementById('adminAllUsername');
    const passwordEl = document.getElementById('adminAllPassword');
    if (!usernameEl || !passwordEl) return;
    const username = (usernameEl.value || '').trim();
    const password = (passwordEl.value || '').trim();
    if (!username) {
        setModalError('Enter username or email.', 'adminAllAccessError');
        return;
    }
    if (!password) {
        setModalError('Enter admin password.', 'adminAllAccessError');
        return;
    }
    if (username !== getAdminUsername() || !(await verifyAdminPassword(password))) {
        setModalError('Invalid username/email or password.', 'adminAllAccessError');
        passwordEl.select();
        return;
    }
    sessionStorage.setItem(SESSION_KEYS.adminAccess, 'true');
    await logAdminAllAccess(username);
    logAudit('Admin (All) access', `${username} opened Admin (All)`);
    closeAdminAllAccessModal();
    const action = pendingAdminAllAccessAction;
    pendingAdminAllAccessAction = null;
    if (typeof action === 'function') action();
}

async function submitAdminPasswordChange() {
    const currentEl = document.getElementById('adminCurrentPassword');
    const nextEl = document.getElementById('adminNewPassword');
    const confirmEl = document.getElementById('adminConfirmPassword');
    if (!currentEl || !nextEl || !confirmEl) return;
    const current = (currentEl.value || '').trim();
    const next = (nextEl.value || '').trim();
    const confirm = (confirmEl.value || '').trim();
    if (!(await verifyAdminPassword(current))) {
        setModalError('Current password is incorrect.', 'adminPasswordError');
        return;
    }
    if (next !== confirm) {
        setModalError('New password confirmation does not match.', 'adminPasswordError');
        return;
    }
    const validation = validateStrongPassword(next);
    if (!validation.ok) {
        setModalError(validation.message, 'adminPasswordError');
        return;
    }
    if (!(await setAdminPassword(next))) {
        setModalError('Failed to save admin password. Ensure it meets the password policy.', 'adminPasswordError');
        return;
    }
    closeAdminPasswordModal();
    logAudit('Admin password changed', `Changed by role: ${adminRole}`);
    showToast('Admin password updated successfully.', 'success');
}

function openAdminPasswordModalFromAuth() {
    closeAdminAuthModal();
    openAdminPasswordModal();
}

function changeAdminPassword() {
    if (!requireAdminAccess(() => changeAdminPassword())) return;
    openAdminPasswordModal();
}

function requireAdminAccess(onSuccess = null, triggerEvent = null) {
    const adminFlag = sessionStorage.getItem(SESSION_KEYS.adminAccess);
    if (adminFlag === 'true' || adminFlag === 'granted') return true;
    openAdminAuthModal(onSuccess, triggerEvent);
    return false;
}

function canAccessAdminMenuForAccount(key, account) {
    if (!key || !account || account.active === false) return false;
    const isAdminUser = key === 'admin';
    if (isAdminUser) return true;
    if (account.adminOnly === true) return true;
    const perms = normalizeUserPermissions(account.permissions, false);
    const team = account.team || jfaProfiles[key]?.team || '';
    return perms.admin === true && Boolean(team);
}

function requireAdminMenuAccess(onSuccess = null, triggerEvent = null) {
    const key = normalizeJfaName(appUser);
    const accounts = getUserAccounts();
    const account = accounts[key];
    const menuFlag = sessionStorage.getItem(SESSION_KEYS.adminMenuAccess);
    if ((menuFlag === 'true' || menuFlag === 'granted') && canAccessAdminMenuForAccount(key, account)) {
        return true;
    }
    openAdminMenuAuthModal(onSuccess, triggerEvent);
    return false;
}

function maskSensitive(value, visiblePrefix = 2, visibleSuffix = 2) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (raw.length <= visiblePrefix + visibleSuffix) return `${raw.slice(0, 1)}***`;
    return `${raw.slice(0, visiblePrefix)}${'*'.repeat(Math.max(3, raw.length - visiblePrefix - visibleSuffix))}${raw.slice(-visibleSuffix)}`;
}

function summarizeAddress(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const parts = raw.split(',').map((p) => p.trim()).filter(Boolean);
    if (!parts.length) return maskSensitive(raw, 3, 0);
    return parts.slice(-2).join(', ');
}

const LEARNING_TOPIC_KEYS = ['jfaManual', 'marketing', 'loa', 'five', 'eight', 'fugi', 'impulse', 'cod', 'cross', 'consolidation', 'capital', 'life', 'matla'];

function getDefaultFormsLibrary() {
    return [
        {
            id: 'broker-authority-2026',
            title: 'Broker Authority 2026',
            description: 'Official broker authority form.',
            url: 'Broker Authority 2026 (2) (1)-1.pdf'
        },
        {
            id: 'jfa-tracker-sheet-1',
            title: 'MATLA LIFE JFA TRACKER SHEET 1',
            description: 'Daily tracking sheet.',
            url: 'MATLA LIFE JFA TRACKER SHEET 1.pdf'
        }
    ];
}

function loadFormsLibrary() {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.formsLibrary) || '[]');
    if (Array.isArray(stored) && stored.length) {
        formsLibrary = stored;
    } else {
        formsLibrary = getDefaultFormsLibrary();
        scheduleStorageWrite(STORAGE_KEYS.formsLibrary, JSON.stringify(formsLibrary));
    }
}

function saveFormsLibrary() {
    scheduleStorageWrite(STORAGE_KEYS.formsLibrary, JSON.stringify(formsLibrary));
}

function renderFormsLibrary() {
    const container = document.getElementById('formsList');
    if (!container) return;
    const safeList = Array.isArray(formsLibrary) ? formsLibrary : [];
    if (!safeList.length) {
        container.innerHTML = '<p class="menu-page-note">No forms uploaded yet.</p>';
        return;
    }
    container.innerHTML = safeList.map((form) => {
        const title = escapeHtml(form.title || 'Untitled Form');
        const description = escapeHtml(form.description || 'No description');
        const url = escapeHtml(form.url || '#');
        return `
            <div class="form-card">
                <div>
                    <h4>${title}</h4>
                    <p class="page-subtitle">${description}</p>
                </div>
                <div class="menu-page-actions">
                    <a class="action-btn secondary" href="${url}" target="_blank" rel="noopener">Preview</a>
                    <a class="action-btn secondary" href="${url}" download>Download</a>
                </div>
            </div>
        `;
    }).join('');
}

function capacityFor(facility) {
    const cap = facility.capacity && facility.capacity > 0 ? facility.capacity : MAX_ALLOCATIONS;
    return Math.min(MAX_ALLOCATIONS, cap);
}

function loadCustomFacilities() {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.customFacilities)) || [];
    if (!Array.isArray(stored)) return;
    const maxId = facilities.reduce((max, f) => Math.max(max, f.id), 0);
    let nextId = maxId + 1;
    stored.forEach((facility) => {
        if (!facility || !facility.name) return;
        facilities.push({
            id: nextId++,
            name: facility.name,
            type: facility.type || 'Other',
            area: facility.area || '',
            contact: facility.contact || 'Receptionist',
            phone: facility.phone || 'N/A',
            capacity: facility.capacity || MAX_ALLOCATIONS,
            allocations: facility.allocations || 0,
            visits: facility.visits || [],
            consentForms: facility.consentForms || 0
        });
    });
    sortFacilitiesAlphabetically();
}

function loadFacilityDirectory() {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEYS.facilityDirectory) || '{}');
    facilities.forEach((facility) => {
        const key = normalizeFacilityName(facility.name);
        const record = saved[facility.id] || saved[key];
        if (!record) return;
        facility.name = record.name || facility.name;
        facility.type = record.type || facility.type;
        facility.area = record.area || facility.area;
        facility.contact = record.contact || facility.contact;
        facility.phone = record.phone || facility.phone;
        if (record.status) facility.status = record.status;
    });
    sortFacilitiesAlphabetically();
}

function saveFacilityDirectory() {
    const payload = {};
    facilities.forEach((facility) => {
        payload[facility.id] = {
            name: facility.name || '',
            type: facility.type || 'Other',
            area: facility.area || '',
            contact: facility.contact || 'Receptionist',
            phone: facility.phone || 'N/A',
            status: facility.status || 'Active'
        };
    });
    scheduleStorageWrite(STORAGE_KEYS.facilityDirectory, JSON.stringify(payload));
}

function applyDisabledFacilityFilter() {
    if (!disabledFacilityKeys.size) return;
    for (let i = facilities.length - 1; i >= 0; i--) {
        const key = normalizeFacilityName(facilities[i].name);
        if (disabledFacilityKeys.has(key)) {
            facilities.splice(i, 1);
        }
    }
    sortFacilitiesAlphabetically();
}

function addAllocationFacilities() {
    const maxId = facilities.reduce((max, f) => Math.max(max, f.id), 0);
    let nextId = maxId + 1;
    allocationFacilities.forEach((item) => {
        const rawName = expandFacilityName(item.name);
        const normalized = normalizeFacilityName(rawName);
        const strictKey = normalizeStrictFacilityKey(rawName);
        if (!normalized) return;
        const existing = facilities.find((f) => {
            const byExact = normalizeFacilityName(f.name) === normalized;
            const byStrictAlias = normalizeStrictFacilityKey(f.name) === strictKey;
            // Never replace unrestricted legacy facilities by alias; only exact name match.
            if (byExact) return true;
            if (byStrictAlias && f.hasDayRules === true) return true;
            return false;
        });
        let days = item.days || '';
        let status = item.status || '';
        const daysNorm = days.toLowerCase();
        if ((daysNorm === 'active' || daysNorm === 'inactive') && !status) {
            status = days;
            days = '';
        }
        const allowedDays = parseAllowedDays(days, status);
        if (existing) {
            existing.name = rawName;
            existing.type = item.type || existing.type || detectFacilityType(rawName);
            existing.area = item.location || existing.area || '';
            existing.contact = existing.contact || 'Receptionist';
            existing.phone = existing.phone || 'N/A';
            existing.allowedDays = allowedDays;
            existing.hasDayRules = true;
            existing.status = status || 'Active';
            existing.daysText = days;
            return;
        }
        facilities.push({
            id: nextId++,
            name: rawName,
            type: item.type || detectFacilityType(rawName),
            area: item.location || '',
            contact: 'Receptionist',
            phone: 'N/A',
            allocations: 0,
            visits: [],
            consentForms: 0,
            allowedDays,
            hasDayRules: true,
            status: status || 'Active',
            daysText: days
        });
    });
    sortFacilitiesAlphabetically();
    saveFacilityDirectory();
}

function saveCurrentJfa() {
    if (!currentJFA || !currentJFA.facility) {
        localStorage.removeItem(STORAGE_KEYS.currentJfa);
        return;
    }
    const payload = {
        name: currentJFA.name,
        phone: currentJFA.phone,
        team: currentJFA.team,
        facilityId: currentJFA.facility.id,
        timestamp: currentJFA.timestamp,
        checkInTime: currentJFA.checkInTime,
        checkInStatus: currentJFA.checkInStatus,
        leadAutoCount: Number.isFinite(currentJFA.leadAutoCount) ? currentJFA.leadAutoCount : 0,
        manualConsentAdjustment: Number.isFinite(currentJFA.manualConsentAdjustment) ? currentJFA.manualConsentAdjustment : 0,
        physicalConsentForms: Number.isFinite(currentJFA.physicalConsentForms) ? currentJFA.physicalConsentForms : 0,
        consentForms: currentJFA.consentForms ?? 0,
        productive: currentJFA.productive ?? null
    };
    scheduleStorageWrite(STORAGE_KEYS.currentJfa, JSON.stringify(payload));
}

function loadCurrentJfa() {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.currentJfa) || 'null');
    if (!stored || !stored.facilityId) return;
    const facility = getFacilityById(stored.facilityId);
    if (!facility) return;
    const storedLeadAutoCount = Number.isFinite(stored.leadAutoCount) ? stored.leadAutoCount : getTodayLeadCountForName(stored.name);
    const storedPhysical = Number.isFinite(stored.physicalConsentForms)
        ? Math.max(0, stored.physicalConsentForms)
        : Number.isFinite(stored.manualConsentAdjustment)
            ? Math.max(0, stored.manualConsentAdjustment)
            : Math.max(0, (Number(stored.consentForms) || 0) - storedLeadAutoCount);
    currentJFA = {
        name: stored.name,
        phone: stored.phone,
        team: stored.team,
        facility,
        timestamp: stored.timestamp || new Date().toISOString(),
        checkInTime: stored.checkInTime || null,
        checkInStatus: stored.checkInStatus || null,
        leadAutoCount: storedLeadAutoCount,
        manualConsentAdjustment: storedPhysical,
        physicalConsentForms: storedPhysical,
        consentForms: Math.max(0, storedLeadAutoCount + storedPhysical),
        productive: stored.productive ?? null
    };
}

function saveLastJfaIdentity(name, team) {
    if (!name) return;
    const payload = {
        name: formatJfaName(name),
        team: team || '',
        timestamp: new Date().toISOString()
    };
    scheduleStorageWrite(STORAGE_KEYS.lastJfaIdentity, JSON.stringify(payload));
}

function getLeadIdentity() {
    if (appUser) {
        const resolvedKey = resolveAccountKey(appUser);
        const accounts = getUserAccounts();
        const account = accounts[resolvedKey] || null;
        const canonicalName = formatJfaName(account?.username || appUser);
        const profile = jfaProfiles[normalizeJfaName(canonicalName)] || {};
        const saved = getStorageJson(STORAGE_KEYS.lastJfaIdentity, null);
        const team = profile.team || account?.team || saved?.team || '';
        return { name: canonicalName, team };
    }
    if (currentJFA?.name) {
        return { name: formatJfaName(currentJFA.name), team: currentJFA.team || '' };
    }
    const saved = getStorageJson(STORAGE_KEYS.lastJfaIdentity, null);
    if (saved?.name) {
        return { name: formatJfaName(saved.name), team: saved.team || '' };
    }
    return null;
}

function getNotifications() {
    try {
        const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.notifications) || '[]');
        if (!Array.isArray(stored)) return [];
        const cutoff = Date.now() - 1000 * 60 * 60 * 24 * 90;
        return stored.filter((note) => {
            const when = new Date(note.createdAt || 0).getTime();
            return Number.isFinite(when) ? when >= cutoff : true;
        });
    } catch (err) {
        return [];
    }
}

function saveNotifications(list) {
    const safe = Array.isArray(list) ? list : [];
    scheduleStorageWrite(STORAGE_KEYS.notifications, JSON.stringify(safe));
}

function getCurrentAccountRecord() {
    const key = normalizeJfaName(appUser || '');
    const accounts = getUserAccounts();
    return { key, accounts, account: accounts[key] };
}

function getNotificationSeenAt() {
    const { account, key } = getCurrentAccountRecord();
    if (account?.lastNotificationSeenAt) return new Date(account.lastNotificationSeenAt);
    const fallback = localStorage.getItem(`notifSeen:${key}`) || '';
    return fallback ? new Date(fallback) : new Date(0);
}

function setNotificationSeenAt(timestamp = new Date()) {
    const { account, accounts, key } = getCurrentAccountRecord();
    const value = new Date(timestamp).toISOString();
    if (account) {
        account.lastNotificationSeenAt = value;
        accounts[key] = account;
        saveUserAccounts(accounts);
    } else if (key) {
        localStorage.setItem(`notifSeen:${key}`, value);
    }
}

function getAllTeams() {
    const teams = new Set(DEFAULT_TEAM_NAMES);
    Object.values(jfaProfiles || {}).forEach((profile) => {
        if (profile?.team) teams.add(profile.team);
    });
    jfaRecords.forEach((record) => {
        if (record?.team) teams.add(record.team);
    });
    getArchives().forEach((archive) => {
        (archive.records || []).forEach((record) => {
            if (record?.team) teams.add(record.team);
        });
    });
    leadRecords.forEach((lead) => {
        if (lead?.jfaTeam) teams.add(lead.jfaTeam);
    });
    const accounts = getUserAccounts();
    Object.values(accounts || {}).forEach((account) => {
        if (account?.team) teams.add(account.team);
    });
    return [...teams].filter(Boolean).sort();
}

function getTeamLeaderAccounts() {
    const accounts = getUserAccounts();
    return Object.entries(accounts)
        .filter(([key, account]) => key !== 'admin' && account && account.active !== false && normalizeUserPermissions(account.permissions, false).admin === true)
        .map(([key, account]) => {
            const profile = jfaProfiles[key] || {};
            return {
                key,
                username: formatJfaName(account.username || key),
                email: String(account.email || profile.email || '').toLowerCase(),
                team: String(account.team || profile.team || '').trim(),
                active: account.active !== false
            };
        })
        .sort((a, b) => a.team.localeCompare(b.team) || a.username.localeCompare(b.username));
}

function renderTeamPortalButtons() {
    const teams = getAllTeams();
    const adminMenuContainer = document.getElementById('adminTeamPortalButtons');
    if (adminMenuContainer) {
        adminMenuContainer.innerHTML = teams.length
            ? teams.map((team) => {
                const encoded = encodeURIComponent(team);
                return `<button class="action-btn" type="button" onclick="openTeamDetailPage(decodeURIComponent('${encoded}'), false, event)">${escapeHtml(team)} Portal</button>`;
            }).join('')
            : '<p class="menu-page-note">No teams available yet.</p>';
    }
    const adminStandaloneContainer = document.getElementById('adminStandaloneTeamPortalButtons');
    if (adminStandaloneContainer) {
        adminStandaloneContainer.innerHTML = teams.length
            ? teams.map((team) => {
                const encoded = encodeURIComponent(team);
                return `<button class="action-btn secondary" type="button" onclick="openTeamPortalFromAdminStandalone(decodeURIComponent('${encoded}'))">${escapeHtml(team)} Stats</button>`;
            }).join('')
            : '<p class="menu-page-note">No teams available yet.</p>';
    }
}

function refreshTeamSelectOptions() {
    const teams = getAllTeams();
    const jfaTeamSelect = document.getElementById('jfaTeam');
    if (jfaTeamSelect) {
        const current = jfaTeamSelect.value;
        jfaTeamSelect.innerHTML = `<option value="">Select your team</option>${teams.map((team) => `<option value="${escapeHtml(team)}">${escapeHtml(team)}</option>`).join('')}`;
        if (current && teams.includes(current)) jfaTeamSelect.value = current;
    }
    const attendanceTeamFilter = document.getElementById('attendanceTeamFilter');
    if (attendanceTeamFilter) {
        const current = attendanceTeamFilter.value;
        attendanceTeamFilter.innerHTML = `<option value="ALL">All Teams</option>${teams.map((team) => `<option value="${escapeHtml(team)}">${escapeHtml(team)}</option>`).join('')}`;
        if (current && (current === 'ALL' || teams.includes(current))) attendanceTeamFilter.value = current;
    }
}

function getApplicableNotifications() {
    const identity = getLeadIdentity();
    const team = identity?.team || '';
    const userKey = normalizeJfaName(appUser || identity?.name || '');
    const notifications = getNotifications();
    return notifications.filter((note) => {
        if (note.scope === 'ALL') return true;
        if (note.scope === 'TEAM' && team && note.team === team) return true;
        if (note.scope === 'USER' && userKey && normalizeJfaName(note.userKey || '') === userKey) return true;
        return false;
    }).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
}

function getUnreadNotifications() {
    const seenAt = getNotificationSeenAt();
    return getApplicableNotifications().filter((note) => {
        const when = new Date(note.createdAt || 0);
        return when > seenAt;
    });
}

function pushSystemNotification(scope, team, title, message, options = {}) {
    const notifications = getNotifications();
    const normalizedType = String(options?.type || '').trim().toUpperCase();
    const detailsPayload = options?.details && typeof options.details === 'object' ? options.details : null;
    notifications.unshift({
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        scope,
        team: team || '',
        userKey: options?.userKey ? normalizeJfaName(options.userKey) : '',
        type: normalizedType || '',
        preview: options?.preview ? String(options.preview) : '',
        details: detailsPayload || undefined,
        title: title || 'Update',
        message: message || '',
        createdAt: new Date().toISOString(),
        createdBy: formatJfaName(options?.createdBy || 'System') || 'System',
        createdRole: String(options?.createdRole || 'SYSTEM')
    });
    saveNotifications(notifications.slice(0, 200));
    refreshNotificationBadge();
}

function getAdminNotificationRecipientKeys() {
    const accounts = getUserAccounts();
    const recipients = new Set(['admin']);
    Object.entries(accounts).forEach(([rawKey, account]) => {
        const key = normalizeJfaName(rawKey || account?.username || '');
        if (!key || account?.active === false) return;
        if (account?.adminOnly === true || key === 'admin') recipients.add(key);
    });
    return [...recipients].filter(Boolean);
}

function notifyAdminFacilityCreated(facility) {
    if (!facility) return;
    const identity = getLeadIdentity() || {};
    const createdBy = formatJfaName(identity.name || appUser || currentJFA?.name || 'Unknown JFA') || 'Unknown JFA';
    const details = {
        facilityName: facility.name || 'N/A',
        facilityType: facility.type || 'Other',
        contactPerson: facility.contact || 'N/A',
        location: facility.area || 'N/A',
        createdBy,
        team: identity.team || currentJFA?.team || 'No Team'
    };
    const recipients = getAdminNotificationRecipientKeys();
    const summary = `${createdBy} submitted a new facility. Open to view details.`;
    recipients.forEach((adminKey) => {
        pushSystemNotification('USER', '', 'New Facility Submitted', summary, {
            userKey: adminKey,
            type: 'FACILITY_CREATED',
            preview: `${createdBy} added a facility request.`,
            details,
            createdBy,
            createdRole: 'JFA'
        });
    });
}

function pushUserNotification(scope, team, title, message) {
    const identity = getLeadIdentity();
    const actorName = formatJfaName(appUser || identity?.name || 'Admin');
    const actorKey = normalizeJfaName(appUser || identity?.name || '');
    const notifications = getNotifications();
    notifications.unshift({
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        scope,
        team: team || '',
        title: title || 'Update',
        message: message || '',
        createdAt: new Date().toISOString(),
        createdBy: actorName,
        createdByKey: actorKey,
        createdRole: adminRole || 'ADMIN'
    });
    saveNotifications(notifications.slice(0, 200));
    refreshNotificationBadge();
}

function getRecentSentTeamNotifications(teamName, limit = 5) {
    const targetTeam = String(teamName || '').trim();
    if (!targetTeam) return [];
    const identity = getLeadIdentity();
    const actorKey = normalizeJfaName(appUser || identity?.name || '');
    if (!actorKey) return [];
    return getNotifications()
        .filter((note) => {
            if (note?.scope !== 'TEAM') return false;
            if (normalizeJfaName(note.team || '') !== normalizeJfaName(targetTeam)) return false;
            const senderKey = normalizeJfaName(note.createdByKey || note.createdBy || '');
            return senderKey === actorKey;
        })
        .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
        .slice(0, Math.max(1, Number(limit) || 5));
}

function getLeaderboardSnapshot() {
    try {
        const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.leaderboardSnapshot) || '{}');
        return stored && typeof stored === 'object' ? stored : {};
    } catch (err) {
        return {};
    }
}

function saveLeaderboardSnapshot(snapshot) {
    const safe = snapshot && typeof snapshot === 'object' ? snapshot : {};
    scheduleStorageWrite(STORAGE_KEYS.leaderboardSnapshot, JSON.stringify(safe));
}

function maybeNotifyLeaderboardChange(now, dailyBestJfa, dailyBestTeam, weeklyBestJfa, weeklyBestTeam) {
    const snapshot = getLeaderboardSnapshot();
    const dayKey = todayKey();
    const weekKey = dateKeyLocal(getStartOfWeek(now));
    const dailySnapshot = snapshot.daily || {};
    const weeklySnapshot = snapshot.weekly || {};

    const dailyJfaName = dailyBestJfa?.name || '-';
    const dailyTeamName = dailyBestTeam?.name || '-';
    const weeklyJfaName = weeklyBestJfa?.name || '-';
    const weeklyTeamName = weeklyBestTeam?.name || '-';

    if (dailySnapshot.date !== dayKey || dailySnapshot.jfa !== dailyJfaName) {
        if (dailyJfaName && dailyJfaName !== '-') {
            pushSystemNotification('ALL', '', 'Leaderboard Update', `Daily top JFA: ${dailyJfaName} (${dailyBestJfa?.value || 0}).`);
        }
    }
    if (dailySnapshot.date !== dayKey || dailySnapshot.team !== dailyTeamName) {
        if (dailyTeamName && dailyTeamName !== '-') {
            pushSystemNotification('ALL', '', 'Leaderboard Update', `Daily top team: ${dailyTeamName} (${dailyBestTeam?.value || 0}).`);
        }
    }
    if (weeklySnapshot.week !== weekKey || weeklySnapshot.jfa !== weeklyJfaName) {
        if (weeklyJfaName && weeklyJfaName !== '-') {
            pushSystemNotification('ALL', '', 'Leaderboard Update', `Weekly top JFA: ${weeklyJfaName} (${weeklyBestJfa?.value || 0}).`);
        }
    }
    if (weeklySnapshot.week !== weekKey || weeklySnapshot.team !== weeklyTeamName) {
        if (weeklyTeamName && weeklyTeamName !== '-') {
            pushSystemNotification('ALL', '', 'Leaderboard Update', `Weekly top team: ${weeklyTeamName} (${weeklyBestTeam?.value || 0}).`);
        }
    }

    snapshot.daily = {
        date: dayKey,
        jfa: dailyJfaName,
        team: dailyTeamName
    };
    snapshot.weekly = {
        week: weekKey,
        jfa: weeklyJfaName,
        team: weeklyTeamName
    };
    saveLeaderboardSnapshot(snapshot);
}

function refreshNotificationBadge() {
    const button = document.getElementById('heroNotificationBtn');
    const badge = document.getElementById('heroNotificationBadge');
    if (!button || !badge) return;
    const unread = getUnreadNotifications();
    const count = unread.length;
    if (count > 0) {
        badge.textContent = String(count);
        button.classList.add('has-unread');
        button.setAttribute('aria-label', `View notifications (${count} unread)`);
        button.title = `${count} unread notifications`;
    } else {
        badge.textContent = '';
        button.classList.remove('has-unread');
        button.setAttribute('aria-label', 'View notifications');
        button.title = 'View notifications';
    }
}

function openNotificationModal() {
    openNotificationDropdown();
}

function markAllNotificationsRead() {
    setNotificationSeenAt(new Date());
    refreshNotificationBadge();
    showToast('Notifications marked as read.', 'success');
    openNotificationDropdown();
}

function clearVisibleNotifications() {
    openNotificationClearConfirmModal();
}

function closeNotificationClearConfirmModal() {
    const modal = document.getElementById('notification-clear-confirm-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function openNotificationClearConfirmModal() {
    const modal = document.getElementById('notification-clear-confirm-modal');
    if (!modal) return;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
}

function confirmClearVisibleNotifications() {
    const all = getNotifications();
    const visible = getFilteredNotificationNotes();
    const visibleIds = new Set(visible.map((note) => String(note.id || '')));
    if (!visibleIds.size) {
        closeNotificationClearConfirmModal();
        showToast('No notifications to clear.', 'error');
        return;
    }
    const remaining = all.filter((note) => !visibleIds.has(String(note.id || '')));
    saveNotifications(remaining);
    setNotificationSeenAt(new Date());
    refreshNotificationBadge();
    notificationPage = 1;
    openNotificationDropdown();
    closeNotificationClearConfirmModal();
    showToast('Notifications cleared.', 'success');
}

function setNotificationFilter(mode = 'all') {
    notificationFilterMode = mode === 'unread' ? 'unread' : 'all';
    notificationPage = 1;
    openNotificationDropdown();
}

function setNotificationSearch(value = '') {
    notificationSearchTerm = String(value || '').trim().toLowerCase();
    notificationPage = 1;
    openNotificationDropdown();
}

function changeNotificationPage(delta = 0) {
    const next = notificationPage + Number(delta || 0);
    notificationPage = next < 1 ? 1 : next;
    openNotificationDropdown();
}

function showLoginNotifications() {
    if (adminRole === 'ADMIN' || adminRole === 'TEAM') return;
    const unread = getUnreadNotifications();
    if (unread.length) {
        openNotificationDropdown();
    }
}

function closeNotificationModal() {
    closeNotificationDropdown();
}

function getFilteredNotificationNotes() {
    const notes = getApplicableNotifications();
    const seenAt = getNotificationSeenAt();
    const filterTerm = String(notificationSearchTerm || '').trim().toLowerCase();
    return notes.filter((note) => {
        if (notificationFilterMode === 'unread') {
            const unread = note.createdAt ? new Date(note.createdAt) > seenAt : false;
            if (!unread) return false;
        }
        if (!filterTerm) return true;
        const scope = note.scope === 'ALL' ? 'all teams' : note.scope === 'USER' ? 'my reminders' : String(note.team || '');
        const haystack = [
            note.title,
            note.message,
            getNotificationPreview(note),
            scope,
            note.createdBy,
            note.team
        ].map((v) => String(v || '').toLowerCase()).join(' ');
        return haystack.includes(filterTerm);
    });
}

function getNotificationPreview(note) {
    if (!note || typeof note !== 'object') return '';
    const preview = String(note.preview || '').trim();
    if (preview) return preview;
    if (String(note.type || '').toUpperCase() === 'FACILITY_CREATED') {
        return 'New facility submitted. Open to view details.';
    }
    return String(note.message || '');
}

function buildNotificationDetailMessage(note) {
    if (!note || typeof note !== 'object') return '';
    if (String(note.type || '').toUpperCase() !== 'FACILITY_CREATED') {
        return String(note.message || '');
    }
    const details = note.details && typeof note.details === 'object' ? note.details : {};
    return [
        `Facility Name: ${details.facilityName || 'N/A'}`,
        `Facility Type: ${details.facilityType || 'N/A'}`,
        `Contact Person: ${details.contactPerson || 'N/A'}`,
        `Location: ${details.location || 'N/A'}`,
        `Added By: ${details.createdBy || 'N/A'}`,
        `Team: ${details.team || 'N/A'}`
    ].join('\n');
}

function renderNotificationDetailHtml(note) {
    if (!note || typeof note !== 'object') return '<p>No details available.</p>';
    if (String(note.type || '').toUpperCase() !== 'FACILITY_CREATED') {
        return `<p>${escapeHtml(note.message || '')}</p>`;
    }
    const details = note.details && typeof note.details === 'object' ? note.details : {};
    return `
        <p><strong>Facility Name:</strong> ${escapeHtml(details.facilityName || 'N/A')}</p>
        <p><strong>Facility Type:</strong> ${escapeHtml(details.facilityType || 'N/A')}</p>
        <p><strong>Contact Person:</strong> ${escapeHtml(details.contactPerson || 'N/A')}</p>
        <p><strong>Location:</strong> ${escapeHtml(details.location || 'N/A')}</p>
        <p><strong>Added By:</strong> ${escapeHtml(details.createdBy || 'N/A')}</p>
        <p><strong>Team:</strong> ${escapeHtml(details.team || 'N/A')}</p>
    `;
}

function openNotificationDropdown() {
    const dropdown = document.getElementById('notification-dropdown');
    const list = document.getElementById('notificationList');
    const markBtn = document.getElementById('notificationMarkReadBtn');
    const clearBtn = document.getElementById('notificationClearBtn');
    const allBtn = document.getElementById('notificationFilterAllBtn');
    const unreadBtn = document.getElementById('notificationFilterUnreadBtn');
    const stats = document.getElementById('notificationStats');
    const pagination = document.getElementById('notificationPagination');
    const prevBtn = document.getElementById('notificationPrevBtn');
    const nextBtn = document.getElementById('notificationNextBtn');
    const pageInfo = document.getElementById('notificationPageInfo');
    if (!dropdown || !list) return;
    const notes = getApplicableNotifications();
    const seenAt = getNotificationSeenAt();
    const searchInput = document.getElementById('notificationSearchInput');
    if (searchInput && searchInput.value !== notificationSearchTerm) {
        searchInput.value = notificationSearchTerm;
    }
    const unreadNotes = notes.filter((note) => note.createdAt ? new Date(note.createdAt) > seenAt : false);
    const filteredNotes = getFilteredNotificationNotes();
    if (allBtn) allBtn.classList.toggle('is-active', notificationFilterMode === 'all');
    if (unreadBtn) unreadBtn.classList.toggle('is-active', notificationFilterMode === 'unread');
    if (stats) {
        stats.innerHTML = `
            <span class="insight-chip">Total: ${notes.length}</span>
            <span class="insight-chip ${unreadNotes.length ? 'danger' : ''}">Unread: ${unreadNotes.length}</span>
            <span class="insight-chip">View: ${notificationFilterMode === 'unread' ? 'Unread' : 'All'}</span>
            ${notificationSearchTerm ? `<span class="insight-chip">Search: ${escapeHtml(notificationSearchTerm)}</span>` : ''}
        `;
    }
    const totalPages = Math.max(1, Math.ceil(filteredNotes.length / NOTIFICATION_PAGE_SIZE));
    if (notificationPage > totalPages) notificationPage = totalPages;
    const startIndex = (notificationPage - 1) * NOTIFICATION_PAGE_SIZE;
    const pageNotes = filteredNotes.slice(startIndex, startIndex + NOTIFICATION_PAGE_SIZE);
    if (pagination) {
        pagination.style.display = filteredNotes.length > NOTIFICATION_PAGE_SIZE ? 'flex' : 'none';
    }
    if (prevBtn) prevBtn.disabled = notificationPage <= 1;
    if (nextBtn) nextBtn.disabled = notificationPage >= totalPages;
    if (pageInfo) pageInfo.textContent = `Page ${notificationPage} of ${totalPages}`;
    if (!pageNotes.length) {
        list.innerHTML = '<p class="no-data">No notifications yet.</p>';
        if (markBtn) markBtn.style.display = 'none';
        if (clearBtn) clearBtn.style.display = 'none';
    } else {
        if (markBtn) markBtn.style.display = '';
        if (clearBtn) clearBtn.style.display = '';
        list.innerHTML = pageNotes.map((note) => {
            const scope = note.scope === 'ALL'
                ? 'All teams'
                : note.scope === 'USER'
                    ? 'My reminders'
                    : `${note.team || 'Team'}`;
            const when = note.createdAt ? new Date(note.createdAt).toLocaleString('en-ZA') : '—';
            const isUnread = note.createdAt ? new Date(note.createdAt) > seenAt : false;
            const encodedId = encodeURIComponent(String(note.id || ''));
            return `
                <button class="notification-card ${isUnread ? 'is-unread' : ''}" type="button" onclick="openNotificationDetailModal('${encodedId}')">
                    <h4>${escapeHtml(note.title || 'Update')}</h4>
                    <p>${escapeHtml(getNotificationPreview(note))}</p>
                    <div class="notification-meta">
                        <span>${escapeHtml(scope)}</span>
                        <span>${escapeHtml(when)}</span>
                        <span>By ${escapeHtml(note.createdBy || 'Admin')}</span>
                        ${isUnread ? '<span class="notification-new">New</span>' : ''}
                    </div>
                </button>
            `;
        }).join('');
    }
    dropdown.classList.add('is-open');
    dropdown.setAttribute('aria-hidden', 'false');
    positionNotificationDropdown(dropdown);
    setNotificationSeenAt(new Date());
    refreshNotificationBadge();
    requestAnimationFrame(() => {
        document.addEventListener('click', handleNotificationOutsideClick);
        window.addEventListener('resize', handleNotificationPositionUpdate);
        window.addEventListener('scroll', handleNotificationPositionUpdate, true);
        document.addEventListener('keydown', handleNotificationEscape);
        if (searchInput && document.activeElement !== searchInput) {
            searchInput.focus();
        }
    });
}

function openNotificationDetailModal(encodedId) {
    const id = decodeURIComponent(encodedId || '');
    if (!id) return;
    const note = getApplicableNotifications().find((item) => String(item.id || '') === id);
    if (!note) {
        showToast('Notification not found.', 'error');
        return;
    }
    const modal = document.getElementById('notification-detail-modal');
    const title = document.getElementById('notificationDetailTitle');
    const meta = document.getElementById('notificationDetailMeta');
    const body = document.getElementById('notificationDetailBody');
    if (!modal || !title || !meta || !body) return;
    const scope = note.scope === 'ALL' ? 'All teams' : note.scope === 'USER' ? 'My reminders' : (note.team || 'Team');
    const when = note.createdAt ? new Date(note.createdAt).toLocaleString('en-ZA') : '—';
    title.textContent = note.title || 'Notification';
    meta.textContent = `${scope} • ${when} • By ${note.createdBy || 'Admin'}`;
    body.innerHTML = renderNotificationDetailHtml(note);
    body.dataset.message = buildNotificationDetailMessage(note);
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeNotificationDetailModal() {
    const modal = document.getElementById('notification-detail-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function copyNotificationDetail() {
    const body = document.getElementById('notificationDetailBody');
    if (!body) return;
    const msg = String(body.dataset.message || '').trim();
    if (!msg) {
        showToast('No message to copy.', 'error');
        return;
    }
    copyToClipboard(msg, 'Notification copied');
}

function closeNotificationDropdown() {
    const dropdown = document.getElementById('notification-dropdown');
    if (!dropdown) return;
    dropdown.classList.remove('is-open');
    dropdown.setAttribute('aria-hidden', 'true');
    document.removeEventListener('click', handleNotificationOutsideClick);
    window.removeEventListener('resize', handleNotificationPositionUpdate);
    window.removeEventListener('scroll', handleNotificationPositionUpdate, true);
    document.removeEventListener('keydown', handleNotificationEscape);
}

function closeQuickActionsMenu() {
    const menu = document.getElementById('quickActionsMenu');
    const trigger = document.querySelector('.quick-actions-toggle');
    if (menu) {
        menu.classList.remove('is-open');
    }
    if (trigger) {
        trigger.setAttribute('aria-expanded', 'false');
    }
    document.removeEventListener('click', handleQuickActionsOutsideClick, true);
}

function handleQuickActionsOutsideClick(event) {
    const menu = document.getElementById('quickActionsMenu');
    const trigger = document.querySelector('.quick-actions-toggle');
    if (!menu || !trigger) return;
    if (menu.contains(event.target) || trigger.contains(event.target)) return;
    closeQuickActionsMenu();
}

function getQuickActionsContext() {
    const activePageId = document.querySelector('.page.active')?.id || '';
    const inAdminStandalone = activePageId === 'admin-standalone-page' && adminRole === 'ADMIN';
    const inAdminMenu = activeMenuPage === 'admin' && (adminRole === 'ADMIN' || adminRole === 'TEAM');
    const inTeamPortal = activeMenuPage === 'teamDetail' && adminRole === 'TEAM';
    if (inAdminStandalone) return 'admin-standalone';
    if (inAdminMenu) return 'admin-menu';
    if (inTeamPortal) return 'team-portal';
    return 'user';
}

function getQuickActionItems() {
    const context = getQuickActionsContext();
    if (context === 'admin-standalone') {
        return [
            { id: 'admin-leads', label: 'Submitted Leads' },
            { id: 'admin-facilities', label: 'Edit Facilities' },
            { id: 'admin-jfas', label: 'JFA Register' },
            { id: 'admin-fas', label: 'FA Register' },
            { id: 'admin-teams', label: 'Team Leaders' },
            { id: 'admin-clients', label: 'Clients (Secure)' },
            { id: 'admin-notify-all', label: 'Notify Everyone' },
            { id: 'admin-settings', label: 'Security Settings' },
            { id: 'admin-payments', label: 'Payments' },
            { id: 'admin-team-center', label: 'Team Portal Center' }
        ];
    }
    if (context === 'admin-menu') {
        return [
            { id: 'admin-team-center', label: 'Team Portal Center' },
            { id: 'admin-payments', label: 'Payments' },
            { id: 'open-ben-system', label: 'Ben System' },
            { id: 'admin-settings', label: 'Settings' },
            { id: 'admin-notify-all', label: 'Notify Everyone' }
        ];
    }
    if (context === 'team-portal') {
        return [
            { id: 'team-notify', label: 'Notify Team' },
            { id: 'team-settings', label: 'Team Settings' },
            { id: 'team-admin-menu', label: 'Back to Admin Menu' },
            { id: 'open-payments', label: 'Payments' },
            { id: 'open-ben-system', label: 'Ben System' }
        ];
    }
    return [
        { id: 'user-register', label: 'Register' },
        { id: 'user-dbd', label: 'DBD' },
        { id: 'user-stats', label: 'Dashboard' },
        { id: 'open-leads', label: 'Leads' },
        { id: 'open-payments', label: 'Payments' },
        { id: 'open-ben-system', label: 'Ben System' },
        { id: 'open-settings', label: 'Settings' },
        { id: 'sync-now', label: 'Sync Now' }
    ];
}

function runQuickAction(actionId) {
    const id = String(actionId || '').trim();
    if (!id) return;
    switch (id) {
        case 'admin-leads':
            openAdminStandaloneTab('leads');
            break;
        case 'admin-facilities':
            openAdminStandaloneTab('facilities');
            break;
        case 'admin-jfas':
            openAdminStandaloneTab('jfas');
            break;
        case 'admin-fas':
            openAdminStandaloneTab('fas');
            break;
        case 'admin-teams':
            openAdminStandaloneTab('teams');
            break;
        case 'admin-clients':
            openAdminStandaloneTab('clients');
            break;
        case 'admin-notify-all':
            openNotificationComposeModal('ALL');
            break;
        case 'admin-settings':
            if (isAdminStandaloneActive()) {
                openAdminSettingsFromStandalone();
            } else {
                openMenuPage('settings', true, true);
            }
            break;
        case 'admin-payments':
            if (isAdminStandaloneActive()) {
                openAdminPaymentsFromStandalone();
            } else {
                openMenuPage('payments', true, true);
            }
            break;
        case 'admin-team-center':
            if (isAdminStandaloneActive()) {
                openAdminMenuStatsFromStandalone();
            } else {
                openMenuPage('admin', true, true);
            }
            break;
        case 'team-notify':
            openNotificationComposeModal('TEAM', adminTeam || '');
            break;
        case 'team-settings':
            openTeamLeaderSettings();
            break;
        case 'team-admin-menu':
            openMenuPage('admin', true, true);
            break;
        case 'open-leads':
            openMenuPage('leads');
            break;
        case 'open-payments':
            openMenuPage('payments');
            break;
        case 'open-ben-system':
            openMenuPage('benSystem');
            break;
        case 'open-settings':
            openMenuPage('settings');
            break;
        case 'sync-now':
            forceRemoteSyncNow();
            break;
        case 'user-register':
            navigateToRegister();
            break;
        case 'user-dbd':
            navigateToDBD();
            break;
        case 'user-stats':
            navigateToStats();
            break;
        default:
            break;
    }
    closeQuickActionsMenu();
}

function renderQuickActionsMenu() {
    const menu = document.getElementById('quickActionsMenu');
    const trigger = document.querySelector('.quick-actions-toggle');
    if (!menu || !trigger) return;
    const context = getQuickActionsContext();
    const title = context === 'admin-standalone' ? 'Admin Actions' : context === 'admin-menu' || context === 'team-portal' ? 'Portal Actions' : 'Quick Actions';
    trigger.textContent = title;
    trigger.setAttribute('aria-label', title);
    const items = getQuickActionItems();
    menu.innerHTML = items.map((item) =>
        `<button type="button" onclick="runQuickAction('${escapeHtml(item.id)}')">${escapeHtml(item.label)}</button>`
    ).join('');
}

function handleNotificationOutsideClick(event) {
    const dropdown = document.getElementById('notification-dropdown');
    const button = document.getElementById('heroNotificationBtn');
    if (!dropdown || !button) return;
    if (dropdown.contains(event.target) || button.contains(event.target)) return;
    closeNotificationDropdown();
}

function handleNotificationEscape(event) {
    if (event.key === 'Escape') {
        const detailOpen = document.getElementById('notification-detail-modal')?.classList.contains('is-open');
        if (detailOpen) {
            closeNotificationDetailModal();
            return;
        }
        closeNotificationDropdown();
    }
}

function handleNotificationPositionUpdate() {
    const dropdown = document.getElementById('notification-dropdown');
    if (!dropdown || !dropdown.classList.contains('is-open')) return;
    positionNotificationDropdown(dropdown);
}

function positionNotificationDropdown(dropdown) {
    const button = document.getElementById('heroNotificationBtn');
    if (!button || !dropdown) return;
    const mobileViewport = Math.round(window.visualViewport?.height || window.innerHeight || 0);
    if (mobileViewport) {
        dropdown.style.maxHeight = `${Math.max(220, mobileViewport - 24)}px`;
    }
    if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) {
        dropdown.style.left = '8px';
        dropdown.style.right = '8px';
        dropdown.style.top = `${Math.max(8, button.getBoundingClientRect().bottom + 8)}px`;
        return;
    }
    const rect = button.getBoundingClientRect();
    const padding = 12;
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
    const viewportHeight = mobileViewport || window.innerHeight || document.documentElement.clientHeight;
    const dropdownWidth = dropdown.offsetWidth || 320;
    const dropdownHeight = dropdown.offsetHeight || 240;
    dropdown.style.right = 'auto';
    let left = rect.right - dropdownWidth;
    if (left < padding) left = padding;
    if (left + dropdownWidth > viewportWidth - padding) {
        left = Math.max(padding, viewportWidth - dropdownWidth - padding);
    }
    let top = rect.bottom + 10;
    if (top + dropdownHeight > viewportHeight - padding) {
        const above = rect.top - dropdownHeight - 10;
        top = above > padding ? above : Math.max(padding, viewportHeight - dropdownHeight - padding);
    }
    dropdown.style.left = `${Math.round(left)}px`;
    dropdown.style.top = `${Math.round(top)}px`;
}

function openNotificationComposeModal(scope = 'TEAM', teamOverride = '') {
    if (!(adminRole === 'ADMIN' || adminRole === 'TEAM')) {
        showToast('Only team leaders or admin can send notifications.', 'error');
        return;
    }
    if (scope === 'TEAM' && (activeMenuPage === 'teamDetail' || activeMenuPage === 'admin')) {
        const team = teamOverride || adminTeam || '';
        if (!team) {
            showToast('Select a team first.', 'error');
            return;
        }
        openInlineNotificationComposer(activeMenuPage === 'admin' ? 'adminNotificationInline' : 'teamNotificationInline', team);
        return;
    }
    const modal = document.getElementById('notification-compose-modal');
    const title = document.getElementById('notificationComposeTitle');
    const subtitle = document.getElementById('notificationComposeSubtitle');
    const teamGroup = document.getElementById('notificationTeamGroup');
    const teamSelect = document.getElementById('notificationTeamSelect');
    const message = document.getElementById('notificationMessage');
    const titleInput = document.getElementById('notificationTitleInput');
    if (!modal || !title || !subtitle || !teamGroup || !teamSelect || !message || !titleInput) return;
    modal.dataset.scope = scope;
    modal.dataset.team = teamOverride || '';
    message.value = '';
    titleInput.value = '';
    setModalError('', 'notificationComposeError');
    if (scope === 'ALL') {
        title.textContent = 'Send Notification to Everyone';
        subtitle.textContent = 'This message will be visible to all users.';
        teamGroup.style.display = 'none';
    } else {
        title.textContent = 'Send Notification to Team';
        subtitle.textContent = 'Only your team members will see this message.';
        teamGroup.style.display = 'block';
        const teams = getAllTeams();
        teamSelect.innerHTML = teams.map((team) => `<option value="${escapeHtml(team)}">${escapeHtml(team)}</option>`).join('');
        const forcedTeam = teamOverride || (adminRole === 'TEAM' ? adminTeam : '');
        if (forcedTeam) {
            teamSelect.value = forcedTeam;
            teamSelect.disabled = true;
        } else {
            teamSelect.disabled = false;
        }
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => message.focus(), 30);
}

function closeNotificationComposeModal() {
    const modal = document.getElementById('notification-compose-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    setModalError('', 'notificationComposeError');
}

function submitNotificationCompose() {
    const modal = document.getElementById('notification-compose-modal');
    const teamSelect = document.getElementById('notificationTeamSelect');
    const messageEl = document.getElementById('notificationMessage');
    const titleEl = document.getElementById('notificationTitleInput');
    if (!modal || !messageEl || !titleEl) return;
    const scope = modal.dataset.scope === 'ALL' ? 'ALL' : 'TEAM';
    const teamOverride = (modal.dataset.team || '').trim();
    const message = (messageEl.value || '').trim();
    const title = (titleEl.value || '').trim();
    if (message.length < 4) {
        setModalError('Notification message is too short.', 'notificationComposeError');
        return;
    }
    let team = '';
    if (scope === 'TEAM') {
        team = (teamOverride || teamSelect?.value || adminTeam || '').trim();
        if (!team) {
            setModalError('Select a team for this notification.', 'notificationComposeError');
            return;
        }
        if (adminRole === 'TEAM' && adminTeam && normalizeJfaName(team) !== normalizeJfaName(adminTeam)) {
            setModalError('Team leaders can only send notifications to their own team.', 'notificationComposeError');
            return;
        }
    }
    pushUserNotification(scope, team, title || (scope === 'ALL' ? 'Admin Update' : `${team} Update`), message);
    closeNotificationComposeModal();
    refreshNotificationBadge();
    showToast('Notification sent.', 'success');
}

function openInlineNotificationComposer(containerId, teamName) {
    const container = document.getElementById(containerId);
    if (!container) {
        openNotificationComposeModal('TEAM', teamName);
        return;
    }
    const lockedTeam = adminRole === 'TEAM' && adminTeam ? adminTeam : '';
    const team = lockedTeam || teamName || adminTeam || '';
    const allowTeamPick = !team && adminRole !== 'TEAM';
    const teamOptions = getAllTeams()
        .map((teamNameOption) => `<option value="${escapeHtml(teamNameOption)}">${escapeHtml(teamNameOption)}</option>`)
        .join('');
    container.style.display = 'block';
    container.innerHTML = `
        <div class="modal-card">
            <h3>Send Notification (${escapeHtml(team || 'Team')})</h3>
            <p class="page-subtitle">Only ${escapeHtml(team || 'this team')} members will see this message.</p>
            <div class="modal-form-grid">
                ${allowTeamPick ? `
                <div class="form-group">
                    <label for="teamNotifySelect">Select Team</label>
                    <select id="teamNotifySelect">
                        <option value="">Choose a team</option>
                        ${teamOptions}
                    </select>
                </div>
                ` : ''}
                <div class="form-group">
                    <label for="teamNotifyTitle">Title (Optional)</label>
                    <input type="text" id="teamNotifyTitle" placeholder="e.g. Morning Push Update">
                </div>
                <div class="form-group">
                    <label for="teamNotifyMessage">Message</label>
                    <textarea id="teamNotifyMessage" rows="4" placeholder="Type your notification..."></textarea>
                </div>
                <div id="teamNotifyError" class="modal-error" style="display:none;"></div>
                <div class="modal-actions">
                    <button class="action-btn secondary" type="button" onclick="closeInlineNotificationComposer('${containerId}')">Cancel</button>
                    <button class="action-btn" type="button" onclick="submitInlineNotificationComposer('${containerId}')">Send Notification</button>
                </div>
            </div>
        </div>
    `;
    container.dataset.team = team;
    setTimeout(() => document.getElementById('teamNotifyMessage')?.focus(), 30);
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeInlineNotificationComposer(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.style.display = 'none';
    container.innerHTML = '';
    container.dataset.team = '';
}

function submitInlineNotificationComposer(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const selectTeam = (document.getElementById('teamNotifySelect')?.value || '').trim();
    const team = (adminRole === 'TEAM' && adminTeam
        ? adminTeam
        : (selectTeam || container.dataset.team || adminTeam || '')).trim();
    const title = (document.getElementById('teamNotifyTitle')?.value || '').trim();
    const message = (document.getElementById('teamNotifyMessage')?.value || '').trim();
    const errorEl = document.getElementById('teamNotifyError');
    if (!team) {
        if (errorEl) {
            errorEl.textContent = 'Team not found.';
            errorEl.style.display = 'block';
        }
        return;
    }
    if (adminRole === 'TEAM' && adminTeam && normalizeJfaName(team) !== normalizeJfaName(adminTeam)) {
        if (errorEl) {
            errorEl.textContent = 'Team leaders can only notify their own team.';
            errorEl.style.display = 'block';
        }
        return;
    }
    if (message.length < 4) {
        if (errorEl) {
            errorEl.textContent = 'Notification message is too short.';
            errorEl.style.display = 'block';
        }
        return;
    }
    pushUserNotification('TEAM', team, title || `${team} Update`, message);
    closeInlineNotificationComposer(containerId);
    showToast('Notification sent.', 'success');
}

function seedJfaProfilesFromRecords() {
    const combined = [...jfaRecords, ...getArchives().flatMap((a) => a.records || [])];
    combined.forEach((record) => {
        if (!record?.name) return;
        ensureJfaProfile(record.name, { phone: record.phone || '', team: record.team || '' });
    });
    if (currentJFA?.name) {
        ensureJfaProfile(currentJFA.name, { phone: currentJFA.phone || '', team: currentJFA.team || '' });
    }
    saveJfaProfiles();
}

async function getLeadGeolocation() {
    const now = Date.now();
    if (
        leadGeoCache?.coords &&
        Number.isFinite(leadGeoCache.coords.lat) &&
        Number.isFinite(leadGeoCache.coords.lng) &&
        now - (leadGeoCache.capturedAtMs || 0) <= CONFIG.GEOLOCATION_REUSE_WINDOW
    ) {
        return {
            status: 'cached',
            coords: {
                lat: leadGeoCache.coords.lat,
                lng: leadGeoCache.coords.lng,
                accuracy: leadGeoCache.coords.accuracy
            }
        };
    }
    if (!navigator.geolocation) {
        return { status: 'unavailable' };
    }

    const requestPosition = (enableHighAccuracy = false) => new Promise((resolve) => {
        let settled = false;
        const finish = (payload) => {
            if (settled) return;
            settled = true;
            resolve(payload);
        };
        const timeout = setTimeout(() => finish({ status: 'timeout' }), CONFIG.GEOLOCATION_TIMEOUT);
        navigator.geolocation.getCurrentPosition(
            (pos) => {
                clearTimeout(timeout);
                leadGeoCache = {
                    capturedAtMs: Date.now(),
                    coords: {
                        lat: pos.coords.latitude,
                        lng: pos.coords.longitude,
                        accuracy: pos.coords.accuracy
                    }
                };
                finish({
                    status: 'ok',
                    coords: {
                        lat: pos.coords.latitude,
                        lng: pos.coords.longitude,
                        accuracy: pos.coords.accuracy
                    }
                });
            },
            (err) => {
                clearTimeout(timeout);
                const status = err?.code === 1 ? 'denied' : err?.code === 3 ? 'timeout' : 'error';
                finish({ status, message: err?.message || 'Location error' });
            },
            {
                enableHighAccuracy: Boolean(enableHighAccuracy),
                timeout: CONFIG.GEOLOCATION_OPTIONS_TIMEOUT,
                maximumAge: enableHighAccuracy ? 0 : CONFIG.GEOLOCATION_MAX_AGE
            }
        );
    });

    const first = await requestPosition(false);
    if (first?.coords && Number.isFinite(first.coords.lat) && Number.isFinite(first.coords.lng)) return first;
    if (String(first?.status || '').toLowerCase() === 'denied') return first;
    const second = await requestPosition(true);
    if (second?.coords && Number.isFinite(second.coords.lat) && Number.isFinite(second.coords.lng)) return second;
    return second?.status ? second : first;
}

async function preflightLeadGeotagCapture() {
    if (!navigator.onLine && isCloudSyncRequired()) {
        setSyncState('offline');
    }
    const geo = await getLeadGeolocation();
    const hasCoords = Boolean(
        geo?.coords &&
        Number.isFinite(geo.coords.lat) &&
        Number.isFinite(geo.coords.lng)
    );
    const hintEl = document.getElementById('leadSignatureHint');
    if (hintEl) {
        const label = getGeoStatusLabel(geo?.status || 'unknown');
        hintEl.textContent = hasCoords
            ? `Signature ready. Geotag status: ${label}.`
            : `Signature ready. Geotag status: ${label} (required before submit).`;
    }
}

function getGeoStatusLabel(status = '') {
    const key = String(status || '').toLowerCase();
    if (key === 'ok') return 'Captured';
    if (key === 'cached') return 'Captured (Cached)';
    if (key === 'denied') return 'Permission Denied';
    if (key === 'timeout') return 'Timed Out';
    if (key === 'error') return 'Error';
    if (key === 'unavailable') return 'Unavailable';
    return 'Unknown';
}

function getGeoQualityLabel(accuracy) {
    if (!Number.isFinite(accuracy)) return 'Unknown';
    if (accuracy <= 50) return 'High';
    if (accuracy <= 150) return 'Medium';
    return 'Low';
}

function getLeadGeoSummary(lead) {
    const statusKey = String(lead?.geo?.status || 'unknown').toLowerCase();
    const lat = Number(lead?.geo?.coords?.lat);
    const lng = Number(lead?.geo?.coords?.lng);
    const accuracy = Number(lead?.geo?.coords?.accuracy);
    const hasCoords = Number.isFinite(lat) && Number.isFinite(lng);
    const coordsText = hasCoords ? `${lat.toFixed(5)}, ${lng.toFixed(5)}` : 'Unavailable';
    const accuracyText = Number.isFinite(accuracy) ? `${Math.round(accuracy)}m` : '—';
    const quality = getGeoQualityLabel(accuracy);
    const mapUrl = hasCoords ? `https://www.google.com/maps?q=${lat.toFixed(6)},${lng.toFixed(6)}` : '';
    const capturedRaw = lead?.geoCapturedAt || lead?.timestamp || '';
    const capturedText = capturedRaw ? new Date(capturedRaw).toLocaleString('en-ZA') : '—';
    return {
        statusKey,
        statusLabel: getGeoStatusLabel(statusKey),
        lat: hasCoords ? Number(lat.toFixed(6)) : null,
        lng: hasCoords ? Number(lng.toFixed(6)) : null,
        accuracy: Number.isFinite(accuracy) ? Math.round(accuracy) : null,
        quality,
        coordsText,
        accuracyText,
        mapUrl,
        capturedRaw,
        capturedText
    };
}

function saveCustomFacility(facility) {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.customFacilities)) || [];
    stored.push({
        name: facility.name,
        type: facility.type || 'Other',
        area: facility.area || '',
        contact: facility.contact || 'Receptionist',
        phone: facility.phone || 'N/A',
        capacity: facility.capacity || MAX_ALLOCATIONS,
        allocations: facility.allocations || 0,
        visits: facility.visits || [],
        consentForms: facility.consentForms || 0
    });
    scheduleStorageWrite(STORAGE_KEYS.customFacilities, JSON.stringify(stored));
    sortFacilitiesAlphabetically();
}

function loadFacilityStats() {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.facilities)) || {};
    facilities.forEach((facility) => {
        const saved = stored[facility.id];
        if (!saved) return;
        facility.allocations = saved.allocations ?? facility.allocations;
        facility.consentForms = saved.consentForms ?? facility.consentForms;
        facility.visits = Array.isArray(saved.visits) ? saved.visits : facility.visits;
    });
}

function saveFacilityStats() {
    const payload = {};
    facilities.forEach((facility) => {
        payload[facility.id] = {
            allocations: facility.allocations,
            consentForms: facility.consentForms,
            visits: facility.visits
        };
    });
    scheduleStorageWrite(STORAGE_KEYS.facilities, JSON.stringify(payload));
}

function goToPage(pageId) {
    if (pageId === 'admin-standalone-page' && adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        pageId = 'landing-page';
    }
    if (typeof closeNotificationDropdown === 'function') {
        closeNotificationDropdown();
    }
    renderQuickActionsMenu();
    closeQuickActionsMenu();
    const pages = document.querySelectorAll('.page');
    const current = document.querySelector('.page.active');
    const overlay = document.getElementById('pageTransitionOverlay');
    const currentId = current?.id || lastActivePageId;
    const currentIndex = PAGE_FLOW_ORDER.indexOf(currentId);
    const nextIndex = PAGE_FLOW_ORDER.indexOf(pageId);
    const direction = currentIndex >= 0 && nextIndex >= 0 && nextIndex < currentIndex ? 'backward' : 'forward';
    const shouldCinematic = !prefersReducedMotion && !document.body.classList.contains('performance');
    document.body.classList.remove('page-direction-forward', 'page-direction-backward');
    document.body.classList.add(direction === 'forward' ? 'page-direction-forward' : 'page-direction-backward');
    if (current) {
        current.classList.add('zoom-exit', `zoom-exit-${direction}`);
    }
    const activate = () => {
        if (typeof window.showPage === 'function') {
            window.showPage(pageId);
        } else {
            pages.forEach(page => page.classList.remove('active'));
            const next = document.getElementById(pageId);
            if (next) next.classList.add('active');
        }
        const nextPage = document.getElementById(pageId);
        if (nextPage) {
            nextPage.classList.add('zoom-enter', `zoom-enter-${direction}`);
            setTimeout(() => nextPage.classList.remove('zoom-enter', 'zoom-enter-forward', 'zoom-enter-backward'), CONFIG.PAGE_TRANSITION_DURATION);
        }
        if (current) {
            current.classList.remove('zoom-exit', 'zoom-exit-forward', 'zoom-exit-backward');
        }
        if (pageId === 'stats-page' || pageId === 'archives-page') {
            setPageLoading(pageId, true);
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    if (pageId === 'stats-page') {
                        updateStatistics();
                    } else {
                        renderArchives();
                    }
                    setTimeout(() => setPageLoading(pageId, false), 240);
                });
            });
        }
        if (pageId === 'assignment-page') {
            renderAssignmentAppointmentReminders();
        }
        if (pageId === 'admin-standalone-page') {
            requestAdminLiveRefresh();
        }
        queueUiRefresh();
    };
    if (overlay && shouldCinematic) {
        overlay.classList.remove('is-active');
        void overlay.offsetWidth;
        overlay.classList.add('is-active');
        setTimeout(activate, current ? CONFIG.PAGE_TRANSITION_OFFSET_LATE : CONFIG.PAGE_TRANSITION_OFFSET_EARLY);
        setTimeout(() => overlay.classList.remove('is-active'), CONFIG.ANIMATION_OVERLAY_DURATION);
    } else {
        setTimeout(activate, current ? CONFIG.PAGE_TRANSITION_FAST : 0);
    }
    updateStepperState(pageId);
    setDataFocusMode(pageId);
    lastActivePageId = pageId;
    scheduleStorageWrite(STORAGE_KEYS.lastPage, pageId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function navigateAdminHome() {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    closeMenuPage();
    renderAdminStandalonePage();
    goToPage('admin-standalone-page');
}

function dateKeyLocal(date) {
    const d = date || new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

function todayKey() {
    return dateKeyLocal(new Date());
}

function recordDateKey(record) {
    if (!record?.timestamp) return '';
    return dateKeyLocal(new Date(record.timestamp));
}

function getTodayLeadCountForName(name) {
    const norm = normalizeJfaName(name);
    if (!norm) return 0;
    const today = todayKey();
    return leadRecords.filter((lead) => normalizeJfaName(lead.jfaName) === norm && dateKeyLocal(new Date(lead.timestamp)) === today).length;
}

function getLatestTodayRecordIndexByName(name) {
    const norm = normalizeJfaName(name);
    if (!norm) return -1;
    const today = todayKey();
    let matchIdx = -1;
    let latestStamp = '';
    jfaRecords.forEach((record, idx) => {
        if (normalizeJfaName(record?.name) !== norm) return;
        if (recordDateKey(record) !== today) return;
        const stamp = record.timestamp || '';
        if (stamp >= latestStamp) {
            latestStamp = stamp;
            matchIdx = idx;
        }
    });
    return matchIdx;
}

function applyLeadSubmissionToDailyStats(name) {
    if (!name) return;
    const leadAutoCount = getTodayLeadCountForName(name);

    if (currentJFA && normalizeJfaName(currentJFA.name) === normalizeJfaName(name) && recordDateKey(currentJFA) === todayKey()) {
        const physicalForms = Number.isFinite(currentJFA.physicalConsentForms)
            ? Math.max(0, currentJFA.physicalConsentForms)
            : Number.isFinite(currentJFA.manualConsentAdjustment)
                ? Math.max(0, currentJFA.manualConsentAdjustment)
                : 0;
        currentJFA.leadAutoCount = leadAutoCount;
        currentJFA.manualConsentAdjustment = physicalForms;
        currentJFA.physicalConsentForms = physicalForms;
        currentJFA.consentForms = Math.max(0, leadAutoCount + physicalForms);
        saveCurrentJfa();
    }

    const idx = getLatestTodayRecordIndexByName(name);
    if (idx >= 0) {
        const record = jfaRecords[idx];
        const previous = Number.isFinite(record.consentForms) ? record.consentForms : 0;
        const physicalForms = Number.isFinite(record.physicalConsentForms)
            ? Math.max(0, record.physicalConsentForms)
            : Number.isFinite(record.manualConsentAdjustment)
                ? Math.max(0, record.manualConsentAdjustment)
            : previous - (Number.isFinite(record.leadAutoCount) ? record.leadAutoCount : 0);
        record.leadAutoCount = leadAutoCount;
        record.manualConsentAdjustment = Math.max(0, physicalForms);
        record.physicalConsentForms = Math.max(0, physicalForms);
        record.consentForms = Math.max(0, leadAutoCount + record.physicalConsentForms);
        const delta = record.consentForms - previous;
        if (delta !== 0 && record.facility?.id) {
            const facility = getFacilityById(record.facility.id);
            if (facility) {
                facility.consentForms = Math.max(0, (facility.consentForms || 0) + delta);
            }
            saveFacilityStats();
        }
        scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
        const lastDbd = JSON.parse(localStorage.getItem(STORAGE_KEYS.lastDbd) || 'null');
        if (lastDbd && normalizeJfaName(lastDbd.name) === normalizeJfaName(name) && recordDateKey(lastDbd) === todayKey()) {
            const merged = {
                ...lastDbd,
                consentForms: record.consentForms,
                leadAutoCount,
                manualConsentAdjustment: record.physicalConsentForms,
                physicalConsentForms: record.physicalConsentForms
            };
            scheduleStorageWrite(STORAGE_KEYS.lastDbd, JSON.stringify(merged));
        }
    }
    syncConsentInputWithAutoCount();
    updateSummary();
    updateStatistics();
    updateHeroSummary();
}

function syncConsentInputWithAutoCount() {
    const input = document.getElementById('consentForms');
    const hint = document.getElementById('consentAutoHint');
    if (!hint) return;
    if (!currentJFA?.name) {
        hint.textContent = 'Digital leads auto-added by system: 0. Physical: 0. Total consent forms: 0.';
        return;
    }
    const leadAutoCount = getTodayLeadCountForName(currentJFA.name);
    const physicalForms = Number.isFinite(currentJFA.physicalConsentForms)
        ? Math.max(0, currentJFA.physicalConsentForms)
        : Number.isFinite(currentJFA.manualConsentAdjustment)
            ? Math.max(0, currentJFA.manualConsentAdjustment)
            : 0;
    const suggestedPhysical = physicalForms;
    const suggestedTotal = Math.max(0, leadAutoCount + physicalForms);
    currentJFA.leadAutoCount = leadAutoCount;
    currentJFA.physicalConsentForms = physicalForms;
    currentJFA.manualConsentAdjustment = physicalForms;
    currentJFA.consentForms = suggestedTotal;
    if (input) {
        const currentValue = parseInt(input.value, 10);
        if (Number.isNaN(currentValue) || currentValue === (Number.isFinite(currentJFA.physicalConsentForms) ? currentJFA.physicalConsentForms : 0)) {
            input.value = String(suggestedPhysical);
        }
    }
    hint.textContent = `Digital leads auto-added by system: ${leadAutoCount}. Physical: ${suggestedPhysical}. Total consent forms: ${suggestedTotal}.`;
}

function classifyCheckIn(date) {
    const d = date || new Date();
    const totalMinutes = d.getHours() * 60 + d.getMinutes();
    const onTimeLimit = 7 * 60;
    const cautionLimit = 7 * 60 + 15;
    let status = 'ON_TIME';
    if (totalMinutes > cautionLimit) status = 'LATE';
    else if (totalMinutes > onTimeLimit) status = 'CAUTION';
    const time = d.toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit' });
    return { status, time };
}

function getWorkingDays(start, end) {
    const days = [];
    const cursor = new Date(start);
    cursor.setHours(0, 0, 0, 0);
    const endDate = new Date(end);
    endDate.setHours(23, 59, 59, 999);
    while (cursor <= endDate) {
        const dow = cursor.getDay();
        if (dow !== 0 && dow !== 6) {
            days.push(dateKeyLocal(cursor));
        }
        cursor.setDate(cursor.getDate() + 1);
    }
    return days;
}

function renderAttendancePanel() {
    const container = document.getElementById('attendancePanel');
    if (!container) return;
    const filter = document.getElementById('attendanceTeamFilter')?.value || 'ALL';
    const now = new Date();
    const monthStart = getStartOfMonth(now);
    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, now),
        ...jfaRecords.filter((r) => r.timestamp)
    ];
    const workingDays = getWorkingDays(monthStart, now);

    const map = new Map();
    monthRecords.forEach((r) => {
        if (!r.name) return;
        if (filter !== 'ALL' && r.team !== filter) return;
        if (adminRole === 'TEAM' && adminTeam && r.team !== adminTeam) return;
        const key = normalizeJfaName(r.name);
        const existing = map.get(key) || {
            name: formatJfaName(r.name),
            team: r.team || '—',
            presentDays: new Set(),
            late: 0,
            caution: 0
        };
        const dateKey = recordDateKey(r);
        if (dateKey) existing.presentDays.add(dateKey);
        if (r.checkInStatus === 'LATE') existing.late += 1;
        if (r.checkInStatus === 'CAUTION') existing.caution += 1;
        map.set(key, existing);
    });

    const rows = [...map.values()].map((item) => {
        const absences = Math.max(0, workingDays.length - item.presentDays.size);
        return { ...item, absences };
    }).sort((a, b) => (b.late + b.absences) - (a.late + a.absences));

    if (!rows.length) {
        container.innerHTML = '<p class="no-data">No attendance data yet.</p>';
        return;
    }

    let html = `
        <table class="attendance-table">
            <thead>
                <tr>
                    <th>JFA</th>
                    <th>Team</th>
                    <th>Late</th>
                    <th>Caution</th>
                    <th>Absent</th>
                </tr>
            </thead>
            <tbody>
    `;
    rows.forEach((row) => {
        const absentBadge = row.absences >= 5 ? 'attendance-badge chip-danger' : 'attendance-badge';
        const lateBadge = row.late >= 2 ? 'attendance-badge chip-danger' : 'attendance-badge';
        html += `
            <tr>
                <td>${row.name}</td>
                <td>${row.team}</td>
                <td><span class="${lateBadge}">${row.late}</span></td>
                <td><span class="attendance-badge chip-warn">${row.caution}</span></td>
                <td><span class="${absentBadge}">${row.absences}</span></td>
            </tr>
        `;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function archiveTodayIfNeeded(reason = 'daily') {
    if (!jfaRecords.length) return;
    const archives = JSON.parse(localStorage.getItem(STORAGE_KEYS.archives)) || [];
    const snapshot = {
        date: todayKey(),
        reason,
        records: jfaRecords.map((r) => ({
            name: r.name,
            team: r.team,
            consentForms: r.consentForms,
            productive: r.productive,
            notes: r.notes,
            timestamp: r.timestamp,
            checkInTime: r.checkInTime || null,
            checkInStatus: r.checkInStatus || null,
            facility: {
                name: r.facility?.name ?? '',
                area: r.facility?.area ?? '',
                contact: r.facility?.contact ?? '',
                phone: r.facility?.phone ?? ''
            }
        })),
        facilities: facilities.map((f) => ({
            id: f.id,
            name: f.name,
            area: f.area,
            allocations: f.allocations,
            consentForms: f.consentForms
        }))
    };
    archives.push(snapshot);
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(archives));
}

function checkDailyReset() {
    const lastReset = localStorage.getItem(STORAGE_KEYS.lastReset);
    const resetTime = '00:00';
    const now = new Date();
    const [rh, rm] = resetTime.split(':').map((n) => parseInt(n, 10));
    const resetMinutes = (isNaN(rh) ? 0 : rh) * 60 + (isNaN(rm) ? 0 : rm);
    const nowMinutes = now.getHours() * 60 + now.getMinutes();
    const effectiveDay = new Date(now);
    if (nowMinutes < resetMinutes) {
        effectiveDay.setDate(now.getDate() - 1);
    }
    const effectiveKey = dateKeyLocal(effectiveDay);
    if (lastReset && lastReset === effectiveKey) return;
    if (jfaRecords.length || facilities.some((f) => f.allocations || f.consentForms || f.visits.length)) {
        archiveTodayIfNeeded('daily');
    }
    jfaRecords = [];
    currentJFA = null;
    facilities.forEach((facility) => {
        facility.allocations = 0;
        facility.consentForms = 0;
        facility.visits = [];
    });
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    saveFacilityStats();
    populateFacilityDropdown();
    updateStatistics();
    updateSummary();
    scheduleStorageWrite(STORAGE_KEYS.lastReset, effectiveKey);
    showToast('New day started. Stats archived and reset.', 'success');
}

function ensureDailyContextFresh() {
    const day = todayKey();
    if (day === currentDayKey) return false;
    currentDayKey = day;
    checkWeeklyArchive();
    checkDailyReset();
    return true;
}

function checkWeeklyArchive() {
    const currentKey = getWeekKey(new Date());
    const lastWeek = localStorage.getItem(STORAGE_KEYS.weeklyKey);
    const payload = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedback) || 'null');
    if (!lastWeek) {
        localStorage.setItem(STORAGE_KEYS.weeklyKey, currentKey);
        return;
    }
    if (lastWeek === currentKey) return;
    if (payload && payload.weekKey && Array.isArray(payload.entries) && payload.entries.length) {
        const archive = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedbackArchive) || '[]');
        archive.unshift({ weekKey: payload.weekKey, entries: payload.entries });
        scheduleStorageWrite(STORAGE_KEYS.weeklyFeedbackArchive, JSON.stringify(archive.slice(0, 12)));
    }
    scheduleStorageWrite(STORAGE_KEYS.weeklyFeedback, JSON.stringify({ weekKey: currentKey, entries: [] }));
    localStorage.setItem(STORAGE_KEYS.weeklyKey, currentKey);
}

function appendWeeklyFeedback(record) {
    if (!record?.name) return;
    checkWeeklyArchive();
    const weekKey = getWeekKey(new Date(record.timestamp || Date.now()));
    const payload = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedback) || 'null');
    const entries = payload?.weekKey === weekKey && Array.isArray(payload.entries) ? payload.entries : [];
    entries.push({
        weekKey,
        date: recordDateKey(record),
        name: record.name,
        team: record.team || '',
        productive: record.productive || '',
        consentForms: record.consentForms || 0,
        notes: record.notes || ''
    });
    scheduleStorageWrite(STORAGE_KEYS.weeklyFeedback, JSON.stringify({ weekKey, entries }));
}

function getWeeklyFeedbackFor(name) {
    const normalized = normalizeJfaName(name);
    const payload = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedback) || 'null');
    if (!payload?.entries) return [];
    return payload.entries.filter((e) => normalizeJfaName(e.name) === normalized);
}

function getArchivedWeeklyFeedbackFor(name) {
    const normalized = normalizeJfaName(name);
    const archive = JSON.parse(localStorage.getItem(STORAGE_KEYS.weeklyFeedbackArchive) || '[]');
    return archive.map((bucket) => ({
        weekKey: bucket.weekKey,
        entries: (bucket.entries || []).filter((e) => normalizeJfaName(e.name) === normalized)
    })).filter((bucket) => bucket.entries.length);
}

function startDayBoundaryWatcher() {
    if (dayBoundaryWatcher) {
        clearInterval(dayBoundaryWatcher);
    }
    dayBoundaryWatcher = setInterval(() => {
        const nextDay = todayKey();
        if (nextDay === currentDayKey) return;
        currentDayKey = nextDay;
        checkWeeklyArchive();
        checkDailyReset();
        renderAdminInsights();
        renderAdminTeamDetails();
        if (adminRole === 'TEAM' && adminTeam) {
            renderTeamDetailPage(adminTeam);
        } else if (adminRole === 'ADMIN') {
            renderTeamDetailPage('ALL');
        }
    }, 30000);
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) {
        alert(message);
        return;
    }
    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(6px)';
        setTimeout(() => toast.remove(), CONFIG.TOAST_FADE_DURATION);
    }, CONFIG.TOAST_DURATION);
}

function animateCount(el, target, suffix = '') {
    if (!el) return;
    const current = parseInt(el.getAttribute('data-value') || '0', 10);
    const start = isNaN(current) ? 0 : current;
    const end = Number.isFinite(target) ? target : 0;
    if (start === end) {
        el.textContent = `${end}${suffix}`;
        el.setAttribute('data-value', String(end));
        return;
    }
    const duration = CONFIG.ANIMATION_DURATION;
    const startTime = performance.now();
    const step = (now) => {
        const t = Math.min(1, (now - startTime) / duration);
        const value = Math.round(start + (end - start) * t);
        el.textContent = `${value}${suffix}`;
        if (t < 1) {
            requestAnimationFrame(step);
        } else {
            el.setAttribute('data-value', String(end));
        }
    };
    requestAnimationFrame(step);
}

function pulseHeroMetric(el, nextValue) {
    if (!el) return;
    const previous = Number(el.getAttribute('data-last-value') || '0');
    const current = Number(nextValue || 0);
    if (!Number.isFinite(previous) || previous === current) {
        el.setAttribute('data-last-value', String(current));
        return;
    }
    const cls = current > previous ? 'metric-up' : 'metric-down';
    el.classList.remove('metric-up', 'metric-down');
    void el.offsetWidth;
    el.classList.add(cls);
    el.setAttribute('data-last-value', String(current));
    setTimeout(() => el.classList.remove(cls), 450);
}

function getHeroDailyTargetContext() {
    let dailyTarget = CONFIG.DAILY_TARGET;
    let carryover = 0;
    if (adminRole === 'PERSONAL' && getLeadIdentity()?.name) {
        const now = new Date();
        const weekRecords = getScopedRecordsByRange(getStartOfWeek(now), now);
        const carry = getPersonalCarryoverTarget(now, weekRecords, CONFIG.DAILY_TARGET);
        dailyTarget = carry.dueToday;
        carryover = carry.carryover;
    }
    return { dailyTarget, carryover };
}

function updateHeroContext(todayRecords, totalForms, totalRegistrations, targetCtx) {
    const headlineEl = document.getElementById('heroHeadline');
    const subEl = document.getElementById('heroSubheadline');
    const assistEl = document.getElementById('heroAssistHint');
    const dailyStatEl = document.getElementById('heroDailyTargetStat');
    const weeklyStatEl = document.getElementById('heroWeeklyTargetStat');
    const monthlyStatEl = document.getElementById('heroMonthlyTargetStat');
    if (dailyStatEl) dailyStatEl.textContent = String(CONFIG.DAILY_TARGET);
    if (weeklyStatEl) weeklyStatEl.textContent = String(CONFIG.WEEKLY_TARGET);
    if (monthlyStatEl) monthlyStatEl.textContent = String(CONFIG.MONTHLY_TARGET);

    const identity = getLeadIdentity();
    const todayGap = Math.max(0, targetCtx.dailyTarget - totalForms);
    const weekStart = getStartOfWeek(new Date());
    const weekRecords = getScopedRecordsByRange(weekStart, new Date());
    const weekForms = getScopedConsentFormsTotalForRange(weekStart, new Date());
    const weekGap = Math.max(0, CONFIG.WEEKLY_TARGET - weekForms);

    if (adminRole === 'ADMIN') {
        if (headlineEl) headlineEl.textContent = 'Master Logger Command Center';
        if (subEl) subEl.textContent = 'Company-wide live performance, register health, and risk visibility.';
        if (assistEl) assistEl.textContent = `Today: ${totalRegistrations} registrations, ${totalForms} forms. Weekly gap: ${weekGap}.`;
        return;
    }
    if (adminRole === 'TEAM') {
        if (headlineEl) headlineEl.textContent = "There's no elevator to success, You'll have to take the Stairs.";
        if (subEl) subEl.textContent = 'Track team output, attendance, and intervention risk in real time.';
        if (assistEl) assistEl.textContent = `Team output today: ${totalForms} forms. Weekly gap: ${weekGap}.`;
        return;
    }
    const name = identity?.name ? formatJfaName(identity.name) : 'JFA';
    if (headlineEl) headlineEl.textContent = `${name} Daily Mission`;
    if (subEl) subEl.textContent = 'Own your day: register, execute, submit, and stay above target.';
    if (assistEl) {
        if (todayGap > 0) {
            assistEl.textContent = `Target gap: ${todayGap} today${targetCtx.carryover ? ` (carryover ${targetCtx.carryover})` : ''}. Next: close the gap before day end.`;
        } else {
            assistEl.textContent = 'On track for today. Next: keep momentum and protect weekly target.';
        }
    }
}

function updateHeroSummary() {
    if (ensureDailyContextFresh()) return;
    const today = todayKey();
    const todayRecords = getScopedRecords().filter((r) => recordDateKey(r) === today);
    const totalRegistrations = todayRecords.length;
    const totalForms = getScopedConsentFormsTotalForRange(getStartOfDay(new Date()), new Date());
    const targetCtx = getHeroDailyTargetContext();
    const regEl = document.getElementById('heroRegistrations');
    const formsEl = document.getElementById('heroForms');
    pulseHeroMetric(regEl, totalRegistrations);
    pulseHeroMetric(formsEl, totalForms);
    animateCount(regEl, totalRegistrations, '');
    animateCount(formsEl, totalForms, '');
    const stickyForms = document.getElementById('stickyTotalForms');
    const stickyProgress = document.getElementById('stickyProgress');
    if (stickyForms) stickyForms.textContent = `${totalForms} forms`;
    if (stickyProgress) {
        const pct = Math.min(100, Math.round((totalForms / Math.max(1, Number(targetCtx.dailyTarget) || CONFIG.DAILY_TARGET)) * 100));
        stickyProgress.textContent = `${pct}% target`;
    }
    updateHeroContext(todayRecords, totalForms, totalRegistrations, targetCtx);
    updateHeroTopList();
    updateHeroProgress(todayRecords, targetCtx.dailyTarget);
    updateHeroLastSubmission(todayRecords);
    refreshNotificationBadge();
}

function updateHeroTopList() {
    const container = document.getElementById('heroTopList');
    if (!container) return;
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    monthEnd.setHours(23, 59, 59, 999);

    const identity = getLeadIdentity();
    const scopeTeam = adminRole === 'TEAM'
        ? adminTeam
        : adminRole === 'PERSONAL'
            ? (identity?.team || '')
            : '';
    const inScopeByTeam = (team) => {
        if (adminRole === 'ADMIN') return true;
        if (scopeTeam) return String(team || '') === String(scopeTeam);
        return adminRole !== 'PERSONAL';
    };

    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, monthEnd),
        ...jfaRecords.filter((r) => {
            if (!r.timestamp) return false;
            const d = new Date(r.timestamp);
            return d >= monthStart && d <= monthEnd;
        })
    ].filter((record) => {
        if (!recordMatchesScope(record)) return false;
        if (!record?.name || isTeamLeaderName(record.name, record.team || '')) return false;
        if (adminRole === 'PERSONAL' && !scopeTeam) {
            return normalizeJfaName(record.name) === normalizeJfaName(identity?.name || '');
        }
        return inScopeByTeam(record.team || '');
    });

    const totals = new Map();
    monthRecords.forEach((record) => {
        const key = normalizeJfaName(record.name);
        if (!key) return;
        const existing = totals.get(key) || { name: formatJfaName(record.name), forms: 0 };
        existing.forms += Number(record.consentForms) || 0;
        totals.set(key, existing);
    });

    const monthLeads = getScopedLeadsInRange(monthStart, monthEnd).filter((lead) => {
        if (!lead?.jfaName) return false;
        if (isTeamLeaderName(lead.jfaName, lead.jfaTeam || '')) return false;
        if (adminRole === 'PERSONAL' && !scopeTeam) {
            return normalizeJfaName(lead.jfaName) === normalizeJfaName(identity?.name || '');
        }
        return inScopeByTeam(lead.jfaTeam || '');
    });
    const leadTotals = buildScopedLeadTotalsMap(monthLeads);
    leadTotals.forEach((entry, key) => {
        if (totals.has(key)) return;
        totals.set(key, { name: entry.name, forms: entry.consentForms });
    });

    if (!totals.size) {
        container.innerHTML = '<span class="hero-top-item">—</span>';
        return;
    }

    const top = [...totals.values()]
        .sort((a, b) => b.forms - a.forms)
        .slice(0, 3);
    const medals = ['1', '2', '3'];
    container.innerHTML = top
        .map((item, idx) => `<span class="hero-top-item"><strong>${medals[idx] || '-'}</strong> ${item.name} (${item.forms})</span>`)
        .join('');
}

function startSummaryLiveWatcher() {
    if (summaryLiveWatcher) {
        clearInterval(summaryLiveWatcher);
    }
    summaryLiveWatcher = setInterval(() => {
        ensureDailyContextFresh();
        updateSummary();
        if (isPageActive('stats-page')) {
            updateStatistics();
        }
        if (activeMenuPage === 'admin') {
            try {
                renderAdminInsights();
                renderAdminTeamDetails();
            } catch (_) {}
        }
        if (isAdminStandaloneActive()) {
            try {
                renderAdminStandaloneInsights();
            } catch (_) {}
        }
        if (activeMenuPage === 'benSystem') {
            renderBenSystemPage();
        }
        if (activeMenuPage === 'appointments') {
            renderAppointmentsPage();
        }
    }, 30000);
}

function startDashboardAutoRefresh() {
    if (dashboardAutoRefreshTimer) {
        clearInterval(dashboardAutoRefreshTimer);
    }
    dashboardAutoRefreshTimer = setInterval(() => {
        if (document.visibilityState !== 'visible') return;
        ensureDailyContextFresh();
        updateHeroSummary();
        if (isPageActive('stats-page')) updateStatistics();
        if (activeMenuPage === 'admin') {
            try {
                renderAdminInsights();
                renderAdminTeamDetails();
            } catch (_) {}
        }
        if (isAdminStandaloneActive()) {
            try {
                renderAdminStandaloneInsights();
            } catch (_) {}
        }
        if (activeMenuPage === 'payments') renderPaymentsPage();
        if (activeMenuPage === 'benSystem') renderBenSystemPage();
    }, 45000);
}

function updateHeroProgress(todayRecords = jfaRecords, dailyTarget = CONFIG.DAILY_TARGET) {
    const progressEl = document.getElementById('heroTargetProgress');
    const valueEl = document.getElementById('heroTargetValue');
    if (!progressEl || !valueEl) return;
    const totalForms = getScopedConsentFormsTotalForRange(getStartOfDay(new Date()), new Date());
    const target = Math.max(1, Number(dailyTarget) || CONFIG.DAILY_TARGET);
    const prevPct = Number(progressEl.getAttribute('data-pct') || '0');
    const pct = Math.min(100, Math.round((totalForms / target) * 100));
    progressEl.style.width = `${pct}%`;
    valueEl.textContent = `${pct}% (${totalForms} / ${target})`;
    progressEl.classList.remove('metric-up', 'metric-down');
    if (pct !== prevPct) {
        progressEl.classList.add(pct > prevPct ? 'metric-up' : 'metric-down');
        setTimeout(() => progressEl.classList.remove('metric-up', 'metric-down'), 450);
    }
    progressEl.setAttribute('data-pct', String(pct));
}

function updateHeroLastSubmission(todayRecords = jfaRecords) {
    const el = document.getElementById('heroLastSubmission');
    if (!el) return;
    if (!todayRecords.length) {
        el.textContent = '—';
        return;
    }
    const latest = [...todayRecords]
        .filter((r) => r.timestamp)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
    if (!latest) {
        el.textContent = '—';
        return;
    }
    el.textContent = new Date(latest.timestamp).toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit' });
}

function updateLastSaved() {
    const el = document.getElementById('offlineStatus');
    if (!el) return;
    const stamp = new Date().toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit' });
    el.setAttribute('data-last-saved', stamp);
    if (navigator.onLine) {
        setSyncState('saved');
    }
}

function setSyncState(state) {
    const el = document.getElementById('offlineStatus');
    const heroStatus = document.getElementById('heroStatusRibbon');
    if (!el) return;
    el.classList.remove('is-online', 'is-offline', 'is-syncing', 'is-saved');
    if (state === 'offline') {
        el.classList.add('is-offline');
        if (heroStatus) heroStatus.textContent = 'System: Offline Mode (local data active)';
    } else if (state === 'error') {
        el.classList.add('is-offline');
        if (heroStatus) heroStatus.textContent = 'System: Cloud sync issue (local data active)';
    } else if (state === 'syncing') {
        el.classList.add('is-online', 'is-syncing');
        if (heroStatus) heroStatus.textContent = 'System: Syncing secure cloud backup...';
    } else if (state === 'saved') {
        el.classList.add('is-online', 'is-saved');
        const stamp = new Date().toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit' });
        if (heroStatus) heroStatus.textContent = `System: Synced at ${stamp}`;
    } else {
        el.classList.add(navigator.onLine ? 'is-online' : 'is-offline');
        if (heroStatus) heroStatus.textContent = navigator.onLine ? 'System: Online' : 'System: Offline';
    }
    refreshPlatformStatusPanel();
    refreshSettingsSyncPanel();
}

function setDataFocusMode(pageId, menuPage = '') {
    const dataPages = new Set(['stats-page', 'archives-page']);
    const dataMenuPages = new Set(['admin', 'teamDetail', 'archivedJfas', 'leads', 'benSystem']);
    const hasDataFocus = dataPages.has(pageId) || dataMenuPages.has(menuPage);
    document.body.classList.toggle('data-focus', hasDataFocus);
}

function setPageLoading(pageId, loading) {
    const page = document.getElementById(pageId);
    if (!page) return;
    page.classList.toggle('page-loading', Boolean(loading));
}

function markKeyActionButtons() {
    const selectors = [
        '#leadForm button[type="submit"]',
        '#dbdForm button[type="submit"]',
        '#stats-page button[onclick="exportStatsCsv()"]',
        '#stats-page button[onclick="showCompleteDaySummary()"]',
        '#reset-modal button[onclick="confirmResetAllDataFromModal()"]'
    ];
    selectors.forEach((selector) => {
        const button = document.querySelector(selector);
        if (button) button.classList.add('key-action');
    });
}

let heroListData = [];
let heroListTitle = 'Details';

function renderHeroList(query = '') {
    const bodyEl = document.getElementById('heroListBody');
    const titleEl = document.getElementById('heroListTitle');
    if (!bodyEl || !titleEl) return;
    titleEl.textContent = heroListTitle;
    const q = query.trim().toLowerCase();
    const filtered = heroListData.filter((item) => item.name.toLowerCase().includes(q));
    if (!filtered.length) {
        bodyEl.innerHTML = '<p class="no-data">No matches found.</p>';
        return;
    }
    const highlight = (text) => {
        if (!q) return escapeHtml(text);
        const idx = text.toLowerCase().indexOf(q);
        if (idx === -1) return escapeHtml(text);
        const before = escapeHtml(text.slice(0, idx));
        const match = escapeHtml(text.slice(idx, idx + q.length));
        const after = escapeHtml(text.slice(idx + q.length));
        return `${before}<mark class="hero-mark">${match}</mark>${after}`;
    };
    bodyEl.innerHTML = filtered
        .map((item) => `<div class="hero-list-item" data-name="${escapeHtml(item.name)}" data-team="${escapeHtml(item.team || '')}"><strong>${highlight(item.name)}</strong><span>${escapeHtml(item.meta)}</span></div>`)
        .join('');
}

function openHeroListModal(title, items) {
    const modal = document.getElementById('hero-list-modal');
    const titleEl = document.getElementById('heroListTitle');
    const bodyEl = document.getElementById('heroListBody');
    const searchEl = document.getElementById('heroListSearch');
    if (!modal || !titleEl || !bodyEl) return;
    heroListTitle = title;
    heroListData = items;
    if (searchEl) {
        searchEl.value = '';
        searchEl.oninput = () => renderHeroList(searchEl.value);
    }
    renderHeroList('');
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
}

function closeHeroListModal() {
    const modal = document.getElementById('hero-list-modal');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
}

function openHeroJfaModal(title, html) {
    const modal = document.getElementById('hero-jfa-modal');
    const titleEl = document.getElementById('heroJfaTitle');
    const bodyEl = document.getElementById('heroJfaBody');
    if (!modal || !titleEl || !bodyEl) return;
    titleEl.textContent = title;
    bodyEl.innerHTML = html;
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
}

function closeHeroJfaModal() {
    const modal = document.getElementById('hero-jfa-modal');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
}

function showHeroRegistrationsList() {
    const today = todayKey();
    const todayRecords = jfaRecords.filter((r) => recordDateKey(r) === today);
    if (!todayRecords.length) {
        openHeroListModal('Registrations Today', []);
        return;
    }
    const map = new Map();
    todayRecords.forEach((r) => {
        if (!r.name) return;
        const team = r.team || 'Team —';
        const key = `${normalizeJfaName(r.name)}||${team}`;
        if (!map.has(key)) {
            map.set(key, { name: formatJfaName(r.name), meta: team, team });
        }
    });
    const items = [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
    openHeroListModal('Registrations Today', items);
}

function showHeroFormsList() {
    const today = todayKey();
    const withForms = jfaRecords
        .filter((r) => recordDateKey(r) === today)
        .filter((r) => (r.consentForms || 0) > 0);
    if (!withForms.length) {
        openHeroListModal('Consent Forms Today', []);
        return;
    }
    const totals = new Map();
    withForms.forEach((r) => {
        if (!r.name) return;
        const key = normalizeJfaName(r.name);
        const existing = totals.get(key) || { name: formatJfaName(r.name), forms: 0 };
        existing.forms += r.consentForms || 0;
        totals.set(key, existing);
    });
    const items = [...totals.values()]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((item) => ({ name: item.name, meta: `${item.forms} forms`, team: '' }));
    openHeroListModal('Consent Forms Today', items);
}

function showHeroJfaStats(name, team) {
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    monthEnd.setHours(23, 59, 59, 999);

    const normalizedTarget = normalizeJfaName(name);
    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, monthEnd),
        ...jfaRecords.filter((r) => {
            if (!r.timestamp) return false;
            const d = new Date(r.timestamp);
            return d >= monthStart && d <= monthEnd;
        })
    ].filter((r) => normalizeJfaName(r.name) === normalizedTarget && (!team || r.team === team));

    const records = monthRecords;
    if (!records.length) {
        openHeroJfaModal('JFA Stats', '<p class="no-data">No stats available for this JFA this month.</p>');
        return;
    }
    const totalForms = records.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const productiveCount = records.filter((r) => r.productive === 'YES').length;
    const last = records[records.length - 1];
    const facilities = [...new Set(records.map((r) => r.facility?.name).filter(Boolean))].join(', ');
    const allMonth = [
        ...getArchiveRangeRecords(monthStart, monthEnd),
        ...jfaRecords.filter((r) => r.timestamp)
    ];
    const totals = new Map();
    allMonth.forEach((r) => {
        if (!r.name) return;
        const key = normalizeJfaName(r.name);
        totals.set(key, (totals.get(key) || 0) + (r.consentForms || 0));
    });
    const ranked = [...totals.entries()].sort((a, b) => b[1] - a[1]);
    const rankIndex = ranked.findIndex(([n]) => n === normalizedTarget);
    const rank = rankIndex === -1 ? '—' : `${rankIndex + 1} / ${ranked.length}`;
    const html = `
        <div class="hero-jfa-grid">
            <div class="hero-jfa-card"><strong>${name}</strong><span>JFA Name</span></div>
            <div class="hero-jfa-card"><strong>${team || '—'}</strong><span>Team</span></div>
            <div class="hero-jfa-card"><strong>${totalForms}</strong><span>Forms This Month</span></div>
            <div class="hero-jfa-card"><strong>${productiveCount}</strong><span>Productive Visits</span></div>
            <div class="hero-jfa-card"><strong>${rank}</strong><span>Leaderboard Rank</span></div>
            <div class="hero-jfa-card"><strong>${last?.facility?.name ?? '—'}</strong><span>Last Facility</span></div>
        </div>
        <div class="hero-jfa-card"><strong>Facilities Visited</strong><span>${facilities || '—'}</span></div>
    `;
    openHeroJfaModal(`${name} — Stats`, html);
}

function updateResumeBanner() {
    const banner = document.getElementById('resumeBanner');
    const text = document.getElementById('resumeBannerText');
    if (!banner) return;
    if (currentJFA && currentJFA.facility) {
        banner.style.display = 'flex';
        if (text) {
            text.textContent = `Assigned to ${currentJFA.facility.name}. Continue to DBD or Stats.`;
        }
    } else {
        banner.style.display = 'none';
    }
}

function updateCoverageByArea() {
    const container = document.getElementById('areaCoverage');
    if (!container) return;
    const scoped = getScopedRecords();
    if (!scoped.length) {
        container.innerHTML = '<p class="no-data">No coverage data yet.</p>';
        return;
    }
    const counts = new Map();
    scoped.forEach((r) => {
        const area = r.facility?.area || 'Unknown';
        counts.set(area, (counts.get(area) || 0) + 1);
    });
    const chips = [...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([area, count]) => `<span class="coverage-chip">${area}: ${count}</span>`)
        .join('');
    container.innerHTML = chips;
}

function updateAlertPanel() {
    const panel = document.getElementById('alertPanel');
    if (!panel) return;
    const scoped = getScopedRecords();
    const counts = new Map();
    scoped.forEach((record) => {
        const id = record.facility?.id;
        if (!id) return;
        counts.set(id, (counts.get(id) || 0) + 1);
    });
    const fullFacilities = facilities.filter((f) => (counts.get(f.id) || 0) >= capacityFor(f));
    const overCapacity = facilities.filter((f) => (counts.get(f.id) || 0) > capacityFor(f));
    const unassigned = scoped.filter((r) => !r.facility).length;
    panel.innerHTML = `
        <div class="alert-item"><strong>Facilities full:</strong> ${fullFacilities.length}</div>
        <div class="alert-item"><strong>Over-capacity:</strong> ${overCapacity.length}</div>
        <div class="alert-item"><strong>Unassigned JFAs:</strong> ${unassigned}</div>
    `;
}

function renderTeamHeatmap() {
    const container = document.getElementById('teamHeatmap');
    if (!container) return;
    const now = new Date();
    const today = todayKey();
    const scoped = getScopedRecords();
    const todayRecords = scoped.filter((r) => recordDateKey(r) === today);
    const weekRecords = getArchiveRangeRecords(getStartOfWeek(now), now).concat(todayRecords).filter(recordMatchesScope);
    const monthRecords = getArchiveRangeRecords(getStartOfMonth(now), now).concat(todayRecords).filter(recordMatchesScope);
    const teams = adminRole === 'TEAM' && adminTeam
        ? [adminTeam]
        : adminRole === 'PERSONAL' && currentJFA?.team
            ? [currentJFA.team]
            : ['Team Thando', 'Team Thato', 'Team Rhulani'];
    const all = [];
    teams.forEach((team) => {
        const todayTotal = todayRecords.filter((r) => r.team === team).reduce((s, r) => s + (r.consentForms || 0), 0);
        const weekTotal = weekRecords.filter((r) => r.team === team).reduce((s, r) => s + (r.consentForms || 0), 0);
        const monthTotal = monthRecords.filter((r) => r.team === team).reduce((s, r) => s + (r.consentForms || 0), 0);
        all.push({ team, todayTotal, weekTotal, monthTotal });
    });
    const max = Math.max(1, ...all.map((t) => t.monthTotal));
    container.innerHTML = all.map((t) => {
        const intensity = Math.round((t.monthTotal / max) * 40 + 10);
        return `<div class="heatmap-cell" style="background: rgba(242, 106, 33, ${intensity / 100});">
            <strong>${t.team}</strong><br>
            Today: ${t.todayTotal} • Week: ${t.weekTotal} • Month: ${t.monthTotal}
        </div>`;
    }).join('');
}

function renderFacilityForecast() {
    const container = document.getElementById('facilityForecast');
    if (!container) return;
    const now = new Date();
    const start = new Date(now);
    start.setDate(now.getDate() - 6);
    const scoped = getScopedRecords();
    const rangeRecords = getArchiveRangeRecords(start, now)
        .concat(scoped.filter((r) => r.timestamp))
        .filter(recordMatchesScope);
    const totals = new Map();
    rangeRecords.forEach((r) => {
        const name = r.facility?.name;
        if (!name) return;
        totals.set(name, (totals.get(name) || 0) + 1);
    });
    const top = [...totals.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    if (!top.length) {
        container.innerHTML = '<p class="no-data">No forecast data yet.</p>';
        return;
    }
    container.innerHTML = top.map(([name, visits]) => {
        const avg = (visits / 7).toFixed(1);
        return `<div class="forecast-item"><strong>${name}</strong><br>Avg demand: ${avg} visits/day</div>`;
    }).join('');
}

function renderAuditLog() {
    const container = document.getElementById('auditLog');
    if (!container) return;
    const log = JSON.parse(localStorage.getItem(STORAGE_KEYS.auditLog)) || [];
    const filtered = adminRole === 'TEAM' && adminTeam
        ? log.filter((entry) => (entry.details || '').includes(adminTeam))
        : log;
    if (!filtered.length) {
        container.innerHTML = '<p class="no-data">No activity yet.</p>';
        return;
    }
    container.innerHTML = filtered.slice(0, 10).map((entry) => {
        const time = new Date(entry.time).toLocaleString('en-ZA');
        return `<div class="audit-item">${time} • ${entry.action} • ${entry.details || ''}</div>`;
    }).join('');
}

function updateOfflineStatus() {
    const el = document.getElementById('offlineStatus');
    if (!el) return;
    const isOnline = navigator.onLine;
    const changed = isOnline !== lastOnlineState;
    if (navigator.onLine) {
        el.textContent = 'Online';
        setSyncState('saved');
        refreshRemoteState().catch(() => {});
        scheduleRemoteSync();
    } else {
        el.textContent = 'Offline Ready';
        setSyncState('offline');
    }
    if (changed) {
        showToast(isOnline ? 'Connection restored. Syncing latest data.' : 'You are offline. Changes are saved locally.', isOnline ? 'success' : 'error');
    }
    lastOnlineState = isOnline;
    updateLastSaved();
}

function canNavigateTo(pageId) {
    if (['assignment-page', 'dbd-page', 'stats-page'].includes(pageId)) {
        if (!currentJFA || !currentJFA.facility) {
            showToast('Please register first.', 'error');
            goToPage('registration-page');
            return false;
        }
    }
    return true;
}

function updateStepperState(activePageId) {
    document.body.classList.toggle('admin-standalone-active', activePageId === 'admin-standalone-page');
    const order = [
        'landing-page',
        'registration-page',
        'assignment-page',
        'dbd-page',
        'stats-page',
        'archives-page'
    ];
    const activeIndex = activePageId === 'archives-page'
        ? order.indexOf('stats-page')
        : order.indexOf(activePageId);
    const steps = document.querySelectorAll('.flow-step');
    steps.forEach((step) => {
        const stepNum = step.getAttribute('data-step');
        const stepIndex = stepNum ? parseInt(stepNum, 10) - 1 : -1;
        step.classList.remove('is-active', 'is-complete');
        if (stepIndex === activeIndex) {
            step.classList.add('is-active');
        } else if (stepIndex !== -1 && stepIndex < activeIndex) {
            step.classList.add('is-complete');
        }
    });
    const stepper = document.querySelector('.flow-stepper');
    if (stepper) {
        stepper.style.display = activePageId === 'admin-standalone-page' ? 'none' : '';
        const totalSteps = steps.length || 1;
        const progress = Math.max(0, Math.min(100, (activeIndex / Math.max(1, totalSteps - 1)) * 100));
        stepper.style.setProperty('--step-progress', `${progress}%`);
    }
    const stickySummary = document.getElementById('stickySummary');
    if (stickySummary) {
        // Keep the user productivity chip out of Admin standalone screens to avoid content overlap.
        stickySummary.style.display = activePageId === 'admin-standalone-page' ? 'none' : '';
    }
    updateMobileBottomNavState(activePageId);
}

function updateMobileBottomNavState(activePageId = '') {
    const nav = document.querySelector('.mobile-bottom-nav');
    if (!nav) return;
    const hidden = activePageId === 'admin-standalone-page' || document.body.classList.contains('app-locked');
    nav.style.display = hidden ? 'none' : '';
    const items = nav.querySelectorAll('.mobile-nav-btn');
    items.forEach((item) => {
        const target = item.getAttribute('data-target-page');
        const active = target === activePageId;
        item.classList.toggle('is-active', active);
        item.setAttribute('aria-current', active ? 'page' : 'false');
    });
}

function clearFieldError(container) {
    const group = container?.closest?.('.form-group') || container;
    if (!group) return;
    const existing = group.querySelector('.field-error');
    if (existing) existing.remove();
}

function setFieldError(container, message) {
    const group = container?.closest?.('.form-group') || container;
    if (!group) return;
    let existing = group.querySelector('.field-error');
    if (!existing) {
        existing = document.createElement('div');
        existing.className = 'field-error';
        group.appendChild(existing);
    }
    existing.textContent = message;
}

function hasUnsavedChanges() {
    const registerForm = document.getElementById('jfaForm');
    if (registerForm && isPageActive('registration-page') && !currentJFA) {
        const registerDirty = Boolean(collectRegisterDraft());
        if (registerDirty) return true;
    }
    const form = document.getElementById('dbdForm');
    if (!form) return false;
    const productiveChecked = document.querySelector('input[name="productive"]:checked');
    const consentForms = document.getElementById('consentForms')?.value;
    const notes = document.getElementById('notes')?.value;
    return Boolean(productiveChecked || (consentForms && consentForms !== '0') || (notes && notes.trim().length));
}

function isPageActive(id) {
    const el = document.getElementById(id);
    return el ? el.classList.contains('active') : false;
}

// Initialize
document.addEventListener('DOMContentLoaded', async function() {
    initGlobalErrorGuards();
    await forceOneTimeCachePurgeOnLoad();
    syncVisibleBuildVersion();
    await enforceBuildRefresh();
    loadUiPrefs();
    applyUiPreferences();
    installBrandAssetFallbacks();
    preloadExportLogoDataUrl().catch(() => {});
    bindMobileViewportHeightSync();
    await initializeRemotePersistence();
    applyOneTimeAdminDefaultBootstrap();
    ensureDefaultUserAccount();
    ensureDefaultTeamLeaderAccounts();
    hydrateUsedUsernameRegistry();
    setAuthMode('signin');
    updateAppUserBadge();
    loadFormsLibrary();
    const startupAdminAccessFlag = sessionStorage.getItem(SESSION_KEYS.adminAccess);
    const hasStartupAdminAccess = startupAdminAccessFlag === 'true' || startupAdminAccessFlag === 'granted';
    if ((adminRole === 'ADMIN' || adminRole === 'TEAM') && !hasStartupAdminAccess) {
        adminRole = 'PERSONAL';
        adminTeam = '';
        persistAdminScope();
    }
    loadCustomFacilities();
    addUnrestrictedFacilities2026();
    addAllocationFacilities();
    applyDisabledFacilityFilter();
    loadFacilityDirectory();
    loadFacilityStats();
    loadCurrentJfa();
    seedJfaProfilesFromRecords();
    hydrateAppointmentsFromLeads();
    startAdminLiveRefreshLoop();
    renderTeamPortalButtons();
    refreshTeamSelectOptions();
    startAppointmentReminderWatcher();
    loadResetTime();
    checkDailyReset();
    checkWeeklyArchive();
    startDayBoundaryWatcher();
    bindInactivityWatchers();
    // Load facilities into dropdowns
    populateFacilityDropdown();

    // Setup form handlers
    setupFaRegisterForm();
    setupRegistrationForm();
    setupDBDForm();
    setupRadioHandlers();
    setupLeadForm();
    renderFormsLibrary();

    // Load stats only when stats page is active
    if (jfaRecords.length > 0 && isPageActive('stats-page')) {
        updateStatistics();
    }

    const steps = document.querySelectorAll('.flow-step');
    steps.forEach((step) => {
        step.addEventListener('click', () => {
            const stepNum = step.getAttribute('data-step');
            const mapping = {
                '1': 'landing-page',
                '2': 'registration-page',
                '3': 'assignment-page',
                '4': 'dbd-page',
                '5': 'stats-page'
            };
            const target = mapping[stepNum];
            if (!target) return;
            if (!canNavigateTo(target)) return;
            goToPage(target);
        });
    });

    if (prefersReducedMotion) {
        document.body.classList.add('reduce-motion');
    }
    updateStepperState('landing-page');
    updateSummary();
    updateHeroSummary();
    updateResumeBanner();
    updateOfflineStatus();
    const accounts = getUserAccounts();
    const activeKey = normalizeJfaName(appUser);
    const hasSessionAccount = Boolean(appUser && accounts[activeKey] && accounts[activeKey].active !== false);
    if (!hasSessionAccount) {
        appUser = '';
        sessionStorage.removeItem(SESSION_KEYS.appUser);
        sessionStorage.removeItem(SESSION_KEYS.adminMenuAccess);
        localStorage.removeItem(STORAGE_KEYS.lastJfaIdentity);
        currentJFA = null;
        localStorage.removeItem(STORAGE_KEYS.currentJfa);
        lockAppToAuth();
    } else {
        const account = accounts[activeKey];
        const isAdminUser = activeKey === 'admin';
        const normalizedPermissions = normalizeUserPermissions(account.permissions, isAdminUser);
        const permissionsChanged = JSON.stringify(account.permissions || {}) !== JSON.stringify(normalizedPermissions);
        if (permissionsChanged) {
            account.permissions = normalizedPermissions;
            account.updatedAt = new Date().toISOString();
            accounts[activeKey] = account;
            saveUserAccounts(accounts);
        }
        enforceLoggedUserContext();
        unlockAppFromAuth();
        syncAuthSessionHeartbeat().catch(() => {});
        startCloudPresenceWatcher();
        dispatchMorningAppointmentReminder();
        dispatchOneHourAppointmentReminders();
    }
    updateAppUserBadge();
    updatePermissionDrivenUi();
    initAuthGateBindings();
    registerServiceWorker();
    startSummaryLiveWatcher();
    startDashboardAutoRefresh();
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            ensureDailyContextFresh();
            updateSummary();
        }
    });
    window.addEventListener('storage', (event) => {
        if (!event || !event.key) return;
        const liveKeys = new Set([
            STORAGE_KEYS.records,
            STORAGE_KEYS.leads,
            STORAGE_KEYS.currentJfa,
            STORAGE_KEYS.lastReset
        ]);
        if (!liveKeys.has(event.key)) return;
        if (event.key === STORAGE_KEYS.records) {
            jfaRecords = getStorageJson(STORAGE_KEYS.records, []);
        } else if (event.key === STORAGE_KEYS.leads) {
            leadRecords = getStorageJson(STORAGE_KEYS.leads, []);
        } else if (event.key === STORAGE_KEYS.currentJfa) {
            loadCurrentJfa();
        }
        ensureDailyContextFresh();
        updateSummary();
        if (isPageActive('stats-page')) {
            updateStatistics();
        }
    });
    bindLearningAnchorHandlers();
    parseResetLink();
    initGlobalSearch();
    loadOnboardingState();

    const menuPages = document.querySelectorAll('.menu-page');
    menuPages.forEach((page) => page.addEventListener('scroll', handleMenuPageScroll));

    document.addEventListener('keydown', (event) => {
        if (document.body.classList.contains('app-locked')) return;
        if (event.defaultPrevented) return;
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            openGlobalSearch();
            return;
        }
        if (event.key === 'Escape') {
            const authOpen = document.getElementById('admin-auth-modal')?.classList.contains('is-open');
            const pwdOpen = document.getElementById('admin-password-modal')?.classList.contains('is-open');
            const allOpen = document.getElementById('admin-all-access-modal')?.classList.contains('is-open');
            const adminMenuOpen = document.getElementById('admin-menu-auth-modal')?.classList.contains('is-open');
            const forgotOpen = document.getElementById('forgot-password-modal')?.classList.contains('is-open');
            const resetOpen = document.getElementById('reset-password-modal')?.classList.contains('is-open');
            const benExportOpen = document.getElementById('ben-export-modal')?.classList.contains('is-open');
            const exportReasonOpen = document.getElementById('export-reason-modal')?.classList.contains('is-open');
            const clientsAccessOpen = document.getElementById('clients-access-modal')?.classList.contains('is-open');
            if (authOpen) {
                closeAdminAuthModal();
                event.preventDefault();
                return;
            }
            if (pwdOpen) {
                closeAdminPasswordModal();
                event.preventDefault();
                return;
            }
            if (allOpen) {
                closeAdminAllAccessModal();
                event.preventDefault();
                return;
            }
            if (adminMenuOpen) {
                closeAdminMenuAuthModal();
                event.preventDefault();
                return;
            }
            if (forgotOpen) {
                closeForgotPasswordModal();
                event.preventDefault();
                return;
            }
            if (resetOpen) {
                closeResetPasswordModal();
                event.preventDefault();
                return;
            }
            if (benExportOpen) {
                closeBenExportModal();
                event.preventDefault();
                return;
            }
            if (exportReasonOpen) {
                closeExportReasonModal(true);
                event.preventDefault();
                return;
            }
            if (clientsAccessOpen) {
                closeClientsAccessModal(false);
                event.preventDefault();
                return;
            }
        }
        if (isTypingTarget(event.target)) return;
        if (event.altKey && !event.shiftKey && !event.ctrlKey) {
            if (event.key === '1') {
                openMenuPage('admin');
                event.preventDefault();
            } else if (event.key === '2') {
                openMenuPage('learning');
                event.preventDefault();
            } else if (event.key === '3') {
                openMenuPage('forms');
                event.preventDefault();
            } else if (event.key === '4') {
                openMenuPage('leads');
                event.preventDefault();
            } else if (event.key === '5') {
                openMenuPage('appointments');
                event.preventDefault();
            } else if (event.key === '6') {
                openMenuPage('payments');
                event.preventDefault();
            } else if (event.key === '7') {
                openMenuPage('benSystem');
                event.preventDefault();
            } else if (event.key === '0') {
                closeMenuPage();
                event.preventDefault();
            } else if (event.key.toLowerCase() === 'm') {
                toggleSidebar();
                event.preventDefault();
            }
        }
    });

    document.addEventListener('keydown', (event) => {
        if (document.body.classList.contains('app-locked')) return;
        if (event.key !== 'Escape') return;
        if (document.querySelector('.menu-page.is-open')) {
            closeMenuPage();
        }
    });

    const lastPage = localStorage.getItem(STORAGE_KEYS.lastPage);
    if (hasSessionAccount && adminRole === 'ADMIN') {
        goToPage('admin-standalone-page');
    } else if (lastPage && lastPage !== 'landing-page') {
        if (!canNavigateTo(lastPage)) {
            goToPage('landing-page');
        } else {
            goToPage(lastPage);
        }
    }

    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach((input) => {
        input.addEventListener('input', () => clearFieldError(input));
        input.addEventListener('change', () => clearFieldError(input));
    });

    const paymentsSearch = document.getElementById('paymentsSearchInput');
    if (paymentsSearch) {
        paymentsSearch.addEventListener('input', () => {
            paymentsSearchTerm = paymentsSearch.value.trim();
            renderPaymentsPage();
        });
    }
    const benSearch = document.getElementById('benSystemSearchInput');
    if (benSearch) {
        benSearch.addEventListener('input', () => {
            setBenSystemSearch(benSearch.value);
        });
    }

    window.addEventListener('beforeunload', (e) => {
        if (hasUnsavedChanges()) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    const savedTheme = localStorage.getItem(STORAGE_KEYS.theme);
    if (savedTheme === 'dark') {
        document.body.classList.add('dark');
    }

    const lowPowerDevice = prefersReducedMotion || (typeof navigator.hardwareConcurrency === 'number' && navigator.hardwareConcurrency <= 4);
    document.body.classList.toggle('performance', lowPowerDevice);
    renderQuickActionsMenu();
    markKeyActionButtons();
    setDataFocusMode(document.querySelector('.page.active')?.id || lastActivePageId);

    initHeroStageReveal();
    initHeroParallax();
    initHeroParticles();
    initAmbientGlow();
    initUiRevealObserver();
    refreshKeyboardCards(document);
    initDynamicUiObserver();
    scheduleRemoteSync();

    const heroReg = document.getElementById('heroRegistrations')?.closest('.hero-mini-item');
    const heroForms = document.getElementById('heroForms')?.closest('.hero-mini-item');
    if (heroReg) heroReg.addEventListener('click', showHeroRegistrationsList);
    if (heroForms) heroForms.addEventListener('click', showHeroFormsList);

    const adminScopeNote = document.getElementById('adminScopeNote');
    if (adminScopeNote) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
        adminScopeNote.textContent = `Scope: ${label || 'Personal'}`;
    }

    const heroListBody = document.getElementById('heroListBody');
    if (heroListBody) {
        heroListBody.addEventListener('click', (e) => {
            const item = e.target.closest('.hero-list-item');
            if (!item) return;
            const name = item.getAttribute('data-name');
            const team = item.getAttribute('data-team');
            if (!name) return;
            closeHeroListModal();
            showHeroJfaStats(name, team);
        });
    }

    const lockToggle = document.getElementById('sessionLockToggle');
    if (lockToggle) {
        lockToggle.checked = sessionLockEnabled;
        lockToggle.addEventListener('change', () => {
            sessionLockEnabled = lockToggle.checked;
            scheduleStorageWrite(STORAGE_KEYS.sessionLockEnabled, sessionLockEnabled ? 'true' : 'false');
            if (!sessionLockEnabled) {
                sessionLocked = false;
                scheduleStorageWrite(STORAGE_KEYS.sessionLocked, 'false');
            }
        });
    }

    const searchInput = document.getElementById('jfaSearch');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            jfaSearchTerm = searchInput.value.trim().toLowerCase();
            updateStatistics();
        });
    }

    const attendanceFilter = document.getElementById('attendanceTeamFilter');
    if (attendanceFilter) {
        attendanceFilter.addEventListener('change', renderAttendancePanel);
    }

    const rangeSelect = document.getElementById('exportRange');
    const startInput = document.getElementById('exportStart');
    const endInput = document.getElementById('exportEnd');
    if (rangeSelect && startInput && endInput) {
        const toggleRangeInputs = () => {
            const isCustom = rangeSelect.value === 'custom';
            startInput.disabled = !isCustom;
            endInput.disabled = !isCustom;
        };
        rangeSelect.addEventListener('change', toggleRangeInputs);
        toggleRangeInputs();
    }

    window.addEventListener('online', updateOfflineStatus);
    window.addEventListener('offline', updateOfflineStatus);
    window.addEventListener('beforeinstallprompt', (event) => {
        event.preventDefault();
        deferredInstallPromptEvent = event;
        if (activeMenuPage === 'settings') runCompatibilityCheck(true);
    });
    window.addEventListener('appinstalled', () => {
        deferredInstallPromptEvent = null;
        if (activeMenuPage === 'settings') runCompatibilityCheck(true);
    });
    window.addEventListener('storage', (event) => {
        if (!isAdminLiveRefreshActive()) return;
        const key = String(event?.key || '');
        if (!ADMIN_LIVE_REFRESH_KEYS.has(key)) return;
        requestAdminLiveRefresh();
    });

    const modalOverlays = document.querySelectorAll('.modal-overlay');
    modalOverlays.forEach((overlay) => {
        overlay.addEventListener('click', (e) => {
            if (e.target !== overlay) return;
            if (overlay.id === 'success-modal') closeSuccessModal();
            if (overlay.id === 'reset-modal') closeResetModal();
            if (overlay.id === 'hero-list-modal') closeHeroListModal();
            if (overlay.id === 'admin-jfa-modal') closeAdminJfaModal();
        });
    });

    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        closeSuccessModal();
        closeResetModal();
        closeResetStatsConfirmModal();
        closeHeroListModal();
        closeLeadSignaturePreview();
        closeAppConfirmModal(false);
        closeShortcutsModal();
        const menu = document.getElementById('quickActionsMenu');
        if (menu) menu.classList.remove('is-open');
    });

    document.addEventListener('keydown', (event) => {
        if (document.body.classList.contains('app-locked')) return;
        if (isTypingTarget(event.target)) return;
        if (event.key === '?' || (event.key === '/' && event.shiftKey)) {
            event.preventDefault();
            openShortcutsModal();
        }
        if ((event.ctrlKey || event.metaKey) && String(event.key || '').toLowerCase() === 'k') {
            event.preventDefault();
            openGlobalSearch();
        }
    });

    // Click animations for buttons intentionally disabled.

    const stickySummary = document.getElementById('stickySummary');
    if (stickySummary) {
        stickySummary.setAttribute('role', 'button');
        stickySummary.setAttribute('tabindex', '0');
        stickySummary.setAttribute('aria-expanded', 'true');
        const toggleSticky = () => {
            if (!window.matchMedia('(max-width: 768px)').matches) return;
            const collapsed = stickySummary.classList.toggle('is-collapsed');
            stickySummary.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        };
        stickySummary.addEventListener('click', toggleSticky);
        stickySummary.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleSticky();
            }
        });
    }
});

function initGlobalSearch() {
    const input = document.getElementById('globalSearchInput');
    if (!input) return;
    input.addEventListener('input', () => {
        renderGlobalSearchResults(input.value || '');
    });
}

function openGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    const input = document.getElementById('globalSearchInput');
    if (!modal || !input) return;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    input.value = '';
    renderGlobalSearchResults('');
    setTimeout(() => input.focus(), 30);
}

function closeGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function renderGlobalSearchResults(query) {
    const container = document.getElementById('globalSearchResults');
    if (!container) return;
    const term = String(query || '').trim().toLowerCase();
    if (!term) {
        container.innerHTML = '<p class="menu-page-note">Start typing to search.</p>';
        return;
    }
    const results = [];
    const quickCommands = [
        {
            label: 'Open Admin Menu',
            meta: 'Command',
            action: () => {
                closeGlobalSearch();
                openMenuPage('admin');
            }
        },
        {
            label: 'Open Settings',
            meta: 'Command',
            action: () => {
                closeGlobalSearch();
                openMenuPage('settings');
            }
        },
        {
            label: 'Open Leads',
            meta: 'Command',
            action: () => {
                closeGlobalSearch();
                openMenuPage('leads');
            }
        },
        {
            label: 'Open Payments',
            meta: 'Command',
            action: () => {
                closeGlobalSearch();
                openMenuPage('payments');
            }
        },
        {
            label: 'Open Ben System',
            meta: 'Command',
            action: () => {
                closeGlobalSearch();
                openMenuPage('benSystem');
            }
        }
    ];
    quickCommands.forEach((cmd) => {
        if (cmd.label.toLowerCase().includes(term)) {
            results.push(cmd);
        }
    });
    const leads = getPaymentsScopedLeads();
    leads.forEach((lead) => {
        const name = String(lead.clientNameRaw || lead.clientName || '').toLowerCase();
        const lid = String(lead.leadId || '').toLowerCase();
        if (name.includes(term) || lid.includes(term)) {
            results.push({
                label: `${lead.leadId || 'LID'} • ${lead.clientNameRaw || lead.clientName || 'Client'}`,
                meta: `Lead • ${lead.jfaTeam || 'No Team'}`,
                action: () => {
                    closeGlobalSearch();
                    openMenuPage('payments');
                    setPaymentsTab('pending');
                }
            });
        }
    });
    Object.entries(jfaProfiles).forEach(([key, profile]) => {
        const fullName = formatJfaName(profile?.fullName || `${profile?.name || ''} ${profile?.surname || ''}`.trim() || key);
        if (fullName.toLowerCase().includes(term)) {
            results.push({
                label: fullName,
                meta: `JFA • ${profile?.team || 'No Team'}`,
                action: () => {
                    closeGlobalSearch();
                    openMenuPage('admin');
                    openAdminJfaDetail(fullName, 'admin', true);
                }
            });
        }
    });
    facilities.forEach((facility) => {
        if (!facility?.name) return;
        if (facility.name.toLowerCase().includes(term)) {
            results.push({
                label: facility.name,
                meta: `Facility • ${facility.area || 'Area'}`,
                action: () => {
                    closeGlobalSearch();
                    openMenuPage('admin');
                    openAdminMasterTab('facilities');
                }
            });
        }
    });
    if (!results.length) {
        container.innerHTML = '<p class="menu-page-note">No matches found.</p>';
        return;
    }
    container.innerHTML = results.slice(0, 12).map((item, idx) => `
        <div class="learning-search-item" onclick="globalSearchSelect(${idx})">
            <strong>${escapeHtml(item.label)}</strong>
            <span>${escapeHtml(item.meta)}</span>
        </div>
    `).join('');
    window.globalSearchSelect = (index) => {
        const target = results[index];
        if (target?.action) target.action();
    };
}

function loadOnboardingState() {
    const banner = document.getElementById('onboardingBanner');
    if (!banner) return;
    const dismissed = localStorage.getItem('onboardingDismissed') === 'true';
    banner.style.display = dismissed ? 'none' : 'flex';
}

function dismissOnboarding() {
    localStorage.setItem('onboardingDismissed', 'true');
    const banner = document.getElementById('onboardingBanner');
    if (banner) banner.style.display = 'none';
}

function initHeroParallax() {
    const logo = document.querySelector('.hero-logo');
    const hero = document.querySelector('.hero-section');
    const spotlight = document.querySelector('.hero-spotlight');
    const ribbon = document.querySelector('.hero-ribbon');
    const glass = document.querySelector('.hero-glass');
    if (!logo || !hero || prefersReducedMotion) return;

    const maxTilt = 10;
    let pendingFrame = null;
    let lastEvent = null;
    let heroActive = true;

    const updateFromEvent = () => {
        if (!lastEvent || !heroActive || document.hidden) {
            pendingFrame = null;
            return;
        }
        const event = lastEvent;
        const rect = hero.getBoundingClientRect();
        const x = (event.clientX - rect.left) / rect.width;
        const y = (event.clientY - rect.top) / rect.height;
        const tiltX = (y - 0.5) * -maxTilt;
        const tiltY = (x - 0.5) * maxTilt;
        logo.style.transform = `rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
        if (ribbon) {
            ribbon.style.transform = `translateY(${tiltX * 0.3}px)`;
        }
        if (glass) {
            glass.style.transform = `translateY(${tiltX * 0.2}px)`;
        }
        if (spotlight) {
            spotlight.style.setProperty('--spot-x', `${Math.round(x * 100)}%`);
            spotlight.style.setProperty('--spot-y', `${Math.round(y * 100)}%`);
        }
        pendingFrame = null;
    };

    const handleMove = (event) => {
        lastEvent = event;
        if (!pendingFrame) {
            pendingFrame = requestAnimationFrame(updateFromEvent);
        }
    };

    const reset = () => {
        logo.style.transform = 'rotateX(0deg) rotateY(0deg)';
        if (ribbon) ribbon.style.transform = 'translateY(0)';
        if (glass) glass.style.transform = 'translateY(0)';
        if (spotlight) {
            spotlight.style.setProperty('--spot-x', '50%');
            spotlight.style.setProperty('--spot-y', '35%');
        }
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            heroActive = entry.isIntersecting;
            if (!heroActive) reset();
        });
    }, { threshold: 0.15 });
    observer.observe(hero);

    hero.addEventListener('mousemove', handleMove, { passive: true });
    hero.addEventListener('mouseleave', reset);
}

function initAmbientGlow() {
    if (prefersReducedMotion) return;
    const root = document.documentElement;
    let raf = null;
    let lastX = window.innerWidth * 0.5;
    let lastY = window.innerHeight * 0.35;

    const paint = () => {
        root.style.setProperty('--mx', `${lastX}px`);
        root.style.setProperty('--my', `${lastY}px`);
        raf = null;
    };

    const onMove = (event) => {
        lastX = event.clientX;
        lastY = event.clientY;
        if (!raf) raf = requestAnimationFrame(paint);
    };

    document.addEventListener('pointermove', onMove, { passive: true });
    paint();
}

function initHeroParticles() {
    const container = document.querySelector('.hero-particles');
    if (!container || prefersReducedMotion) return;
    const count = 12;
    container.innerHTML = '';
    for (let i = 0; i < count; i++) {
        const dot = document.createElement('span');
        const top = Math.round(Math.random() * 80 + 10);
        const left = Math.round(Math.random() * 80 + 10);
        const delay = Math.round(Math.random() * -8);
        const duration = 10 + Math.random() * 8;
        dot.style.top = `${top}%`;
        dot.style.left = `${left}%`;
        dot.style.animationDelay = `${delay}s`;
        dot.style.animationDuration = `${duration}s`;
        container.appendChild(dot);
    }
}

function initHeroStageReveal() {
    const heroContent = document.querySelector('.hero-content');
    if (!heroContent) return;
    const staged = heroContent.querySelectorAll('.hero-stage');
    if (!staged.length) return;
    if (prefersReducedMotion) {
        heroContent.classList.add('is-revealed');
        return;
    }
    staged.forEach((item, index) => {
        item.style.setProperty('--stage-delay', `${80 + index * 70}ms`);
    });
    requestAnimationFrame(() => {
        heroContent.classList.add('is-revealed');
    });
}

function refreshUiReveal(root = document) {
    if (!uiRevealObserver || prefersReducedMotion || !root?.querySelectorAll) return;
    const targets = root.querySelectorAll('.insight-card, .admin-jfa-card, .form-card, .learning-search-item, .summary-card, .target-card, .team-card, .facility-card, .assignment-card, .lead-panel, .lead-section');
    let idx = 0;
    targets.forEach((el) => {
        if (el.classList.contains('ui-observed')) return;
        el.classList.add('ui-reveal', 'ui-observed');
        el.style.setProperty('--ui-delay', `${(idx % 8) * 35}ms`);
        uiRevealObserver.observe(el);
        idx += 1;
    });
}

function initUiRevealObserver() {
    if (prefersReducedMotion || typeof IntersectionObserver === 'undefined') return;
    uiRevealObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            entry.target.classList.add('ui-visible');
            uiRevealObserver.unobserve(entry.target);
        });
    }, { threshold: 0.14, rootMargin: '0px 0px -8% 0px' });
    refreshUiReveal(document);
}

function refreshKeyboardCards(root = document) {
    if (!root?.querySelectorAll) return;
    const cards = root.querySelectorAll('.admin-jfa-card, .hero-mini-item, .hero-list-item');
    cards.forEach((card) => {
        if (card.matches('button, a, input, select, textarea')) return;
        if (!card.hasAttribute('tabindex')) card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.classList.add('is-keyboard-card');
        if (card.getAttribute('data-kbd-bound') === '1') return;
        card.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            card.click();
        });
        card.setAttribute('data-kbd-bound', '1');
    });
}

function queueUiRefresh() {
    if (uiRefreshTimer) clearTimeout(uiRefreshTimer);
    uiRefreshTimer = setTimeout(() => {
        refreshUiReveal(document);
        refreshKeyboardCards(document);
    }, 45);
}

function initDynamicUiObserver() {
    if (typeof MutationObserver === 'undefined' || !document.body) return;
    dynamicUiObserver = new MutationObserver(() => queueUiRefresh());
    dynamicUiObserver.observe(document.body, { childList: true, subtree: true });
}

// Populate facility dropdown
function populateFacilityDropdown() {
    const select = document.getElementById('selectedFacility');
    if (!select) return;
    select.innerHTML = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Choose a facility';
    select.appendChild(placeholder);
    const otherOption = document.createElement('option');
    otherOption.value = 'OTHER';
    otherOption.textContent = 'Other (Type My Facility)';
    select.appendChild(otherOption);
    select.dataset.loaded = 'false';
    const countBadge = document.getElementById('facilityFilterCount');
    if (countBadge) {
        countBadge.textContent = `${facilities.length} available`;
    }
}

function renderFacilityOptions(query = '') {
    const select = document.getElementById('selectedFacility');
    if (!select) return;
    const normalizedQuery = query.trim().toLowerCase();
    const availableOnly = document.getElementById('availableTodayOnly')?.checked;
    const filtered = facilities.filter((facility) => {
        if (!normalizedQuery) return true;
        const label = `${facility.name} ${facility.area}`.toLowerCase();
        return label.includes(normalizedQuery);
    });
    const today = new Date();

    select.innerHTML = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Choose a facility';
    select.appendChild(placeholder);

    const otherOption = document.createElement('option');
    otherOption.value = 'OTHER';
    otherOption.textContent = 'Other (Type My Facility)';
    select.appendChild(otherOption);

    const slice = filtered.filter((f) => !availableOnly || isFacilityAvailableToday(f, today));
    slice.forEach((facility) => {
        const cap = capacityFor(facility);
        const dayAllowed = facility.allowedDays ? isFacilityAvailableToday(facility, today) : true;
        const option = document.createElement('option');
        option.value = facility.id;
        const daysLabel = facility.daysText ? ` • ${facility.daysText}` : '';
        option.textContent = `${facility.name} (${facility.area}) - ${facility.allocations}/${cap} allocated${daysLabel}`;
        option.style.backgroundImage = `linear-gradient(90deg, rgba(23, 162, 164, 0.25) ${Math.round((facility.allocations / cap) * 100)}%, transparent ${Math.round((facility.allocations / cap) * 100)}%)`;
        if (facility.allocations >= cap || !dayAllowed) {
            option.disabled = true;
            option.textContent += facility.allocations >= cap ? ' - FULL' : ' - NOT AVAILABLE TODAY';
        }
        select.appendChild(option);
    });

    const totalCount = availableOnly
        ? filtered.filter((f) => isFacilityAvailableToday(f, today)).length
        : filtered.length;
    const showMoreBtn = document.getElementById('showMoreFacilities');
    if (showMoreBtn) showMoreBtn.style.display = 'none';

    const countBadge = document.getElementById('facilityFilterCount');
    if (countBadge) {
        countBadge.textContent = `${totalCount} available`;
    }
    select.dataset.loaded = 'true';
}

function renderAvailableTodayList(date = new Date()) {
    const container = document.getElementById('availableTodayList');
    const select = document.getElementById('selectedFacility');
    if (!container || !select) return;
    const filterInput = document.getElementById('facilityFilter');
    const query = (filterInput?.value || '').trim().toLowerCase();
    const available = facilities.filter((f) => {
        if (!isFacilityAvailableToday(f, date)) return false;
        if (!query) return true;
        const label = `${f.name} ${f.area}`.toLowerCase();
        return label.includes(query);
    });
    if (!available.length) {
        container.innerHTML = '<span class="page-subtitle">No facilities available today.</span>';
        const moreBtn = document.getElementById('availableTodayMore');
        if (moreBtn) moreBtn.style.display = 'none';
        return;
    }
    container.innerHTML = available.slice(0, availableTodayLimit).map((facility) => `
        <button type="button" class="available-chip" data-id="${facility.id}">${facility.name}</button>
    `).join('');
    const chips = container.querySelectorAll('.available-chip');
    chips.forEach((chip) => {
        chip.addEventListener('click', () => {
            const id = parseInt(chip.getAttribute('data-id'), 10);
            if (!Number.isFinite(id)) return;
            select.value = String(id);
        });
    });
    const moreBtn = document.getElementById('availableTodayMore');
    if (moreBtn) {
        moreBtn.style.display = available.length > availableTodayLimit ? 'inline-flex' : 'none';
    }
}

// Setup radio handlers
function setupRadioHandlers() {
    const radios = document.querySelectorAll('input[name="facilityPlan"]');
    const facilitySelection = document.getElementById('facilitySelection');
    const customFields = document.getElementById('customFacilityFields');
    const select = document.getElementById('selectedFacility');
    const autoAssign = document.getElementById('autoAssignedFacility');
    const availableList = document.getElementById('availableTodayList');
    const availableActions = document.querySelector('.available-today-actions');
    if (!facilitySelection) return;
    if (availableList) availableList.style.display = 'none';
    if (availableActions) availableActions.style.display = 'none';

    radios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'PLAN') {
                facilitySelection.style.display = 'block';
                if (select) {
                    select.required = true;
                    select.disabled = false;
                    const otherOpt = select.querySelector('option[value="OTHER"]');
                    if (otherOpt) otherOpt.disabled = false;
                }
                preAssignedFacilityId = null;
                if (autoAssign) autoAssign.style.display = 'none';
            } else {
                facilitySelection.style.display = 'none';
                if (select) {
                    select.required = false;
                    select.value = '';
                    select.disabled = true;
                    const otherOpt = select.querySelector('option[value="OTHER"]');
                    if (otherOpt) otherOpt.disabled = true;
                }
                if (customFields) customFields.style.display = 'none';
                const auto = getRandomAvailableFacility();
                preAssignedFacilityId = auto ? auto.id : null;
                if (preAssignedFacilityId) {
                    showToast('Facility will be allocated automatically.', 'success');
                    if (autoAssign) {
                        autoAssign.style.display = 'block';
                        setElementText('autoAssignedName', auto.name);
                        setElementText('autoAssignedArea', auto.area ? `Area: ${auto.area}` : '');
                    }
                } else {
                    showToast('No facilities available for auto allocation.', 'error');
                    if (autoAssign) autoAssign.style.display = 'none';
                }
            }
        });
    });

    if (select && customFields) {
        select.addEventListener('change', () => {
            if (select.value === 'OTHER') {
                customFields.style.display = 'block';
            } else {
                customFields.style.display = 'none';
            }
        });
    }

    const filterInput = document.getElementById('facilityFilter');
    const clearBtn = document.getElementById('clearFacilityFilter');
    const countBadge = document.getElementById('facilityFilterCount');
    const showMoreBtn = document.getElementById('showMoreFacilities');
    if (filterInput && select) {
        const applyFilter = () => {
            renderFacilityOptions(filterInput.value);
        };

        filterInput.addEventListener('input', applyFilter);
        const loadOnDemand = () => {
            if (select.dataset.loaded === 'true') return;
            renderFacilityOptions(filterInput.value);
        };
        select.addEventListener('focus', loadOnDemand);
        select.addEventListener('click', loadOnDemand);
        const availableOnly = document.getElementById('availableTodayOnly');
        if (availableOnly) {
            availableOnly.addEventListener('change', applyFilter);
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                filterInput.value = '';
                if (availableOnly) availableOnly.checked = false;
                applyFilter();
            });
        }
        const availableMore = document.getElementById('availableTodayMore');
        if (availableMore) {
            availableMore.addEventListener('click', () => {
                availableTodayLimit = 999;
                renderAvailableTodayList();
            });
        }
        if (showMoreBtn) showMoreBtn.style.display = 'none';
    } else if (countBadge) {
        countBadge.textContent = `${facilities.length} available`;
    }
}

function getRandomAvailableFacility() {
    const today = new Date();
    const available = facilities.filter((f) => f.allocations < capacityFor(f) && isFacilityAvailableToday(f, today));
    if (!available.length) return null;
    return available[Math.floor(Math.random() * available.length)];
}

function collectRegisterDraft() {
    const form = document.getElementById('jfaForm');
    if (!form) return null;
    const data = {
        fullName: document.getElementById('fullName')?.value?.trim() || '',
        phoneNumber: document.getElementById('phoneNumber')?.value?.trim() || '',
        jfaTeam: document.getElementById('jfaTeam')?.value || '',
        facilityPlan: document.querySelector('input[name="facilityPlan"]:checked')?.value || '',
        selectedFacility: document.getElementById('selectedFacility')?.value || '',
        facilityFilter: document.getElementById('facilityFilter')?.value || '',
        availableTodayOnly: Boolean(document.getElementById('availableTodayOnly')?.checked),
        customFacilityName: document.getElementById('customFacilityName')?.value?.trim() || '',
        customFacilityType: document.getElementById('customFacilityType')?.value || '',
        customFacilityContact: document.getElementById('customFacilityContact')?.value?.trim() || '',
        customFacilityArea: document.getElementById('customFacilityArea')?.value?.trim() || '',
        customFacilityPhone: document.getElementById('customFacilityPhone')?.value?.trim() || '',
        customFacilityCapacity: document.getElementById('customFacilityCapacity')?.value || ''
    };
    const hasMeaningfulData = Object.values(data).some((value) => {
        if (typeof value === 'boolean') return value;
        return String(value || '').trim().length > 0;
    });
    return hasMeaningfulData ? data : null;
}

function renderRegisterDraftNotice(updatedAt = '') {
    const notice = document.getElementById('registerDraftNotice');
    if (!notice) return;
    const raw = String(updatedAt || '').trim();
    if (!raw) {
        notice.style.display = 'none';
        notice.innerHTML = '';
        return;
    }
    const when = new Date(raw);
    const stamp = Number.isFinite(when.getTime()) ? when.toLocaleString('en-ZA') : raw;
    notice.style.display = '';
    notice.innerHTML = `
        <div class="lead-draft-notice-text">
            Registration draft recovered from <strong>${escapeHtml(stamp)}</strong>.
        </div>
        <div class="lead-draft-notice-actions">
            <button class="action-btn secondary" type="button" onclick="clearRegisterDraft(true)">Discard Draft</button>
        </div>
    `;
}

function saveRegisterDraft() {
    if (currentJFA && !isEditingRegistration) return;
    const payload = collectRegisterDraft();
    if (!payload) {
        localStorage.removeItem(STORAGE_KEYS.registerDraft);
        renderRegisterDraftNotice('');
        return;
    }
    scheduleStorageWrite(STORAGE_KEYS.registerDraft, JSON.stringify({
        updatedAt: new Date().toISOString(),
        data: payload
    }));
}

function loadRegisterDraft() {
    const raw = localStorage.getItem(STORAGE_KEYS.registerDraft);
    if (!raw) return null;
    try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || !parsed.data || typeof parsed.data !== 'object') return null;
        return parsed;
    } catch (_) {
        return null;
    }
}

function applyRegisterDraft() {
    const draft = loadRegisterDraft();
    if (!draft?.data) {
        renderRegisterDraftNotice('');
        return false;
    }
    const data = draft.data;
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.value = String(value ?? '');
    };
    setValue('fullName', data.fullName || '');
    setValue('phoneNumber', data.phoneNumber || '');
    setValue('jfaTeam', data.jfaTeam || '');
    if (data.facilityPlan) {
        const radio = document.querySelector(`input[name="facilityPlan"][value="${data.facilityPlan}"]`);
        if (radio) {
            radio.checked = true;
            radio.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }
    setValue('selectedFacility', data.selectedFacility || '');
    setValue('facilityFilter', data.facilityFilter || '');
    const availableOnly = document.getElementById('availableTodayOnly');
    if (availableOnly) {
        availableOnly.checked = Boolean(data.availableTodayOnly);
        availableOnly.dispatchEvent(new Event('change', { bubbles: true }));
    }
    setValue('customFacilityName', data.customFacilityName || '');
    setValue('customFacilityType', data.customFacilityType || '');
    setValue('customFacilityContact', data.customFacilityContact || '');
    setValue('customFacilityArea', data.customFacilityArea || '');
    setValue('customFacilityPhone', data.customFacilityPhone || '');
    setValue('customFacilityCapacity', data.customFacilityCapacity || '');
    if (data.selectedFacility === 'OTHER') {
        const customFields = document.getElementById('customFacilityFields');
        if (customFields) customFields.style.display = 'block';
    }
    renderRegisterDraftNotice(String(draft.updatedAt || ''));
    return true;
}

function clearRegisterDraft(showMessage = false) {
    localStorage.removeItem(STORAGE_KEYS.registerDraft);
    renderRegisterDraftNotice('');
    if (showMessage) showToast('Registration draft discarded.', 'success');
}

function saveFaAttendanceRecords() {
    scheduleStorageWrite(FA_ATTENDANCE_STORAGE_KEY, JSON.stringify(faAttendanceRecords.slice(0, 2000)));
}

function getTodayFaAttendanceCount() {
    const today = todayKey();
    return faAttendanceRecords.filter((item) => String(item?.dateKey || '') === today).length;
}

function addFaAttendanceEntry(fullName, team = '') {
    const cleanName = formatJfaName(fullName || '');
    if (!cleanName) return { ok: false, message: 'FA name is required.' };
    const dateKey = todayKey();
    const key = normalizeJfaName(cleanName);
    const existing = faAttendanceRecords.find((item) =>
        String(item?.dateKey || '') === dateKey && normalizeJfaName(item?.name || '') === key
    );
    if (existing) {
        return { ok: true, unchanged: true, entry: existing };
    }
    const entry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        dateKey,
        timestamp: new Date().toISOString(),
        name: cleanName,
        team: String(team || '').trim()
    };
    faAttendanceRecords.unshift(entry);
    saveFaAttendanceRecords();
    return { ok: true, unchanged: false, entry };
}

function populateFaAttendanceSelect() {
    const select = document.getElementById('faAttendanceSelect');
    if (!select) return;
    const fas = getFaRegisterDirectory();
    const options = [
        '<option value="">Select FA</option>',
        ...fas.map((fa) => `<option value="${escapeHtml(fa.name || '')}">${escapeHtml(fa.name || '—')} ${fa.team ? `• ${escapeHtml(fa.team)}` : ''}</option>`)
    ];
    select.innerHTML = options.join('');
}

function openFaRegistrationPage() {
    goToPage('fa-registration-page');
}

function closeFaAttendanceModal() {
    const modal = document.getElementById('fa-attendance-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function submitFaAttendance() {
    const select = document.getElementById('faAttendanceSelect');
    const nameInput = document.getElementById('faAttendanceName');
    const hint = document.getElementById('faAttendanceHint');
    const selectedName = String(select?.value || '').trim();
    const typedName = formatJfaName(nameInput?.value || '');
    const fullName = typedName || selectedName;
    if (!fullName) {
        if (hint) hint.textContent = 'Select or type an FA name first.';
        showToast('Select or type FA name first.', 'error');
        return;
    }
    const profile = ensureFaProfile(fullName) || {};
    const result = addFaAttendanceEntry(fullName, profile.team || '');
    if (!result.ok) {
        showToast(result.message || 'Could not capture FA attendance.', 'error');
        return;
    }
    if (nameInput) nameInput.value = '';
    if (select) select.value = '';
    if (hint) {
        hint.textContent = result.unchanged
            ? `${fullName} was already marked present today.`
            : `${fullName} marked present.`;
    }
    showToast(result.unchanged ? 'FA already marked present today.' : 'FA attendance captured.', 'success');
}

function setupFaRegisterForm() {
    populateFaAttendanceSelect();
    const form = document.getElementById('faRegisterForm');
    if (!form) return;
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const nameEl = document.getElementById('faRegisterName');
        const surnameEl = document.getElementById('faRegisterSurname');
        const mobileEl = document.getElementById('faRegisterMobile');
        const emailEl = document.getElementById('faRegisterEmail');
        const teamEl = document.getElementById('faRegisterTeam');
        const statusEl = document.getElementById('faRegisterStatus');
        const fullName = formatJfaName(`${nameEl?.value || ''} ${surnameEl?.value || ''}`);
        const mobile = String(mobileEl?.value || '').trim();
        const email = String(emailEl?.value || '').trim().toLowerCase();
        const team = String(teamEl?.value || '').trim();
        if (!fullName) {
            showToast('FA name and surname are required.', 'error');
            nameEl?.focus();
            return;
        }
        if (!isValidPhone(mobile)) {
            showToast('Please enter a valid mobile number.', 'error');
            mobileEl?.focus();
            return;
        }
        if (!isValidEmail(email)) {
            showToast('Please enter a valid email address.', 'error');
            emailEl?.focus();
            return;
        }
        const key = normalizeJfaName(fullName);
        const profile = ensureFaProfile(fullName, {
            team,
            username: key,
            phone: mobile,
            email,
            status: 'Active'
        }) || {};
        profile.fullName = fullName;
        profile.name = fullName.split(' ')[0] || profile.name || '';
        profile.surname = fullName.split(' ').slice(1).join(' ') || profile.surname || '';
        profile.team = team || profile.team || '';
        profile.phone = mobile;
        profile.email = email;
        profile.username = profile.username || key;
        profile.status = 'Active';
        profile.updatedAt = new Date().toISOString();
        if (!profile.createdAt) profile.createdAt = profile.updatedAt;
        faProfiles[key] = profile;
        saveFaProfiles();
        const attendance = addFaAttendanceEntry(fullName, profile.team || '');
        if (statusEl) {
            statusEl.textContent = attendance.unchanged
                ? 'Registration complete (already marked present today).'
                : 'Registration complete.';
        }
        showToast('FA registration complete.', 'success');
        form.reset();
        setTimeout(() => {
            goToPage('landing-page');
        }, 650);
    });
}

// Setup registration form
function setupRegistrationForm() {
    const form = document.getElementById('jfaForm');
    if (!form) return;
    const nameEl = document.getElementById('fullName');
    const phoneEl = document.getElementById('phoneNumber');
    const draftHandler = debounce(() => saveRegisterDraft(), 500);
    form.addEventListener('input', draftHandler);
    form.addEventListener('change', draftHandler);
    if (nameEl) {
        nameEl.addEventListener('blur', () => {
            nameEl.value = formatJfaName(nameEl.value || '');
        });
    }
    if (phoneEl) {
        phoneEl.addEventListener('input', () => {
            const digits = String(phoneEl.value || '').replace(/\D/g, '').slice(0, 10);
            if (digits.length <= 3) {
                phoneEl.value = digits;
            } else if (digits.length <= 6) {
                phoneEl.value = `${digits.slice(0, 3)} ${digits.slice(3)}`;
            } else {
                phoneEl.value = `${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6)}`;
            }
        });
    }
    if (!currentJFA || isEditingRegistration) {
        applyRegisterDraft();
    }
    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        if (currentJFA && !isEditingRegistration) {
            showToast('You already have an active session. Continue where you left off.', 'error');
            updateResumeBanner();
            navigateToAssignment();
            return;
        }

        const name = document.getElementById('fullName')?.value?.trim() || '';
        const phone = document.getElementById('phoneNumber')?.value?.trim() || '';
        const team = document.getElementById('jfaTeam')?.value || '';
        const planEl = document.querySelector('input[name="facilityPlan"]:checked');
        const planGroup = document.querySelector('input[name="facilityPlan"]')?.closest('.form-group');

        if (!name) {
            setFieldError(document.getElementById('fullName'), 'Please enter your name and surname.');
            return;
        }

        const phoneDigits = phone.replace(/\D/g, '');
        if (phoneDigits.length < 9) {
            setFieldError(document.getElementById('phoneNumber'), 'Please enter a valid phone number.');
            return;
        }

        if (!team) {
            setFieldError(document.getElementById('jfaTeam'), 'Please select your JFA team.');
            return;
        }

        if (!planEl) {
            if (planGroup) {
                setFieldError(planGroup, 'Please select your facility preference.');
            } else {
                showToast('Please select your facility preference.', 'error');
            }
            return;
        }

        const plan = planEl.value;

        let assignedFacility;

        if (plan === 'PLAN') {
            const selectedValue = document.getElementById('selectedFacility')?.value || '';
            if (!selectedValue) {
                setFieldError(document.getElementById('selectedFacility'), 'Please select a valid facility.');
                return;
            }

            if (selectedValue === 'OTHER') {
                const customName = document.getElementById('customFacilityName')?.value?.trim() || '';
                const customType = document.getElementById('customFacilityType')?.value.trim();
                const customContact = document.getElementById('customFacilityContact')?.value?.trim() || '';
                const customArea = document.getElementById('customFacilityArea')?.value?.trim() || '';
                const customPhone = document.getElementById('customFacilityPhone')?.value.trim();
                const customCapacityRaw = document.getElementById('customFacilityCapacity')?.value;
                const customCapacity = customCapacityRaw
                    ? Math.min(MAX_ALLOCATIONS, Math.max(1, parseInt(customCapacityRaw, 10)))
                    : MAX_ALLOCATIONS;

                if (!customName) {
                    setFieldError(document.getElementById('customFacilityName'), 'Please enter a facility name.');
                    return;
                }
                if (!customContact) {
                    setFieldError(document.getElementById('customFacilityContact'), 'Please enter a contact person.');
                    return;
                }
                if (!customType) {
                    setFieldError(document.getElementById('customFacilityType'), 'Please select a facility type.');
                    return;
                }
                if (!customArea) {
                    setFieldError(document.getElementById('customFacilityArea'), 'Please enter the facility location/area.');
                    return;
                }
                if (!customPhone) {
                    setFieldError(document.getElementById('customFacilityPhone'), 'Please enter the facility contact number.');
                    return;
                }
                const normalizedName = normalizeFacilityName(customName);
                const duplicate = facilities.find((f) => normalizeFacilityName(f.name) === normalizedName);
                if (duplicate) {
                    setFieldError(document.getElementById('customFacilityName'), 'This facility already exists in the list.');
                    return;
                }

                const newId = facilities.reduce((max, f) => Math.max(max, f.id), 0) + 1;
                assignedFacility = {
                    id: newId,
                    name: customName,
                    type: customType,
                    area: customArea,
                    contact: customContact,
                    phone: customPhone,
                    capacity: customCapacity,
                    allocations: 0,
                    visits: [],
                    consentForms: 0
                };
                facilities.push(assignedFacility);
                saveCustomFacility(assignedFacility);
                saveFacilityStats();
                populateFacilityDropdown();
                notifyAdminFacilityCreated(assignedFacility);
            } else {
                const selectedId = parseInt(selectedValue, 10);
                assignedFacility = getFacilityById(selectedId);

                if (!assignedFacility) {
                    setFieldError(document.getElementById('selectedFacility'), 'Please select a valid facility.');
                    return;
                }
                if (!isFacilityAvailableToday(assignedFacility, new Date())) {
                    showToast('This facility is not available today. Please select an available facility.', 'error');
                    return;
                }

                if (assignedFacility.allocations >= capacityFor(assignedFacility)) {
                    showToast('This facility is full. Please select another or choose NO PLAN for random allocation.', 'error');
                    return;
                }
            }
        } else {
            // Random allocation to facilities with available allocations
            if (preAssignedFacilityId) {
                const preAssigned = getFacilityById(preAssignedFacilityId);
                if (preAssigned && preAssigned.allocations < capacityFor(preAssigned)) {
                    assignedFacility = preAssigned;
                } else {
                    preAssignedFacilityId = null;
                }
            }

            if (!assignedFacility) {
                const today = new Date();
                const availableFacilities = facilities.filter(f => f.allocations < capacityFor(f) && isFacilityAvailableToday(f, today));
                if (availableFacilities.length === 0) {
                    showToast('No facilities are available for today. Please contact admin.', 'error');
                    return;
                }
                assignedFacility = pickAutoAssignedFacility(availableFacilities);
                if (!assignedFacility) {
                    showToast('No facilities available for smart auto allocation.', 'error');
                    return;
                }
            }
        }

        // Update allocation count
        let skipAllocationIncrement = false;
        if (isEditingRegistration && currentJFA && currentJFA.facility) {
            if (assignedFacility.id === currentJFA.facility.id) {
                skipAllocationIncrement = true;
            } else {
                currentJFA.facility.allocations = Math.max(0, (currentJFA.facility.allocations || 0) - 1);
            }
        }
        if (!skipAllocationIncrement) {
            assignedFacility.allocations++;
        }
        saveFacilityStats();
        populateFacilityDropdown();

        // Create JFA record
        const checkIn = new Date();
        const { status: checkInStatus, time: checkInTime } = classifyCheckIn(checkIn);
        currentJFA = {
            name,
            phone,
            team,
            facility: assignedFacility,
            timestamp: new Date().toISOString(),
            checkInTime,
            checkInStatus,
            leadAutoCount: getTodayLeadCountForName(name),
            manualConsentAdjustment: 0,
            physicalConsentForms: 0,
            consentForms: 0,
            productive: null
        };
        saveCurrentJfa();
        saveLastJfaIdentity(name, team);
        clearRegisterDraft(false);

        // Navigate to assignment page
        showToast(isEditingRegistration ? 'Registration updated.' : 'Registration complete.', 'success');
        logAudit(isEditingRegistration ? 'Registration updated' : 'Registration completed', `${name} • ${team}`);
        updateSummary();
        updateResumeBanner();
        await syncCriticalCloudState('Registration');
        isEditingRegistration = false;
        navigateToAssignment();
    });
}

// Setup DBD form
function setupDBDForm() {
    const form = document.getElementById('dbdForm');
    if (!form) return;
    const consentInput = document.getElementById('consentForms');
    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        if (!currentJFA) {
            showToast('Please register first.', 'error');
            navigateToRegister();
            return;
        }

        const productiveEl = document.querySelector('input[name="productive"]:checked');
        if (!productiveEl) {
            const productiveGroup = document.querySelector('input[name="productive"]')?.closest('.form-group');
            if (productiveGroup) {
                setFieldError(productiveGroup, 'Please select whether the facility was productive.');
            } else {
                showToast('Please select whether the facility was productive.', 'error');
            }
            return;
        }

        const productive = productiveEl.value;
        const leadAutoCount = getTodayLeadCountForName(currentJFA.name);
        const consentRaw = parseInt(document.getElementById('consentForms')?.value || '0', 10);
        const physicalConsentForms = Number.isNaN(consentRaw) ? 0 : Math.max(0, consentRaw);
        const consentForms = physicalConsentForms + leadAutoCount;
        const notes = document.getElementById('notes')?.value || '';
        if (productive === 'NO' && (!notes || !notes.trim())) {
            setFieldError(document.getElementById('notes'), 'Please add a note when not productive.');
            return;
        }

        // Update current JFA record
        currentJFA.productive = productive;
        currentJFA.leadAutoCount = leadAutoCount;
        currentJFA.manualConsentAdjustment = physicalConsentForms;
        currentJFA.physicalConsentForms = physicalConsentForms;
        currentJFA.consentForms = consentForms;
        currentJFA.notes = notes;

        // Update facility stats
        currentJFA.facility.consentForms += consentForms;
        currentJFA.facility.visits.push({
            jfa: currentJFA.name,
            productive: productive === 'YES',
            consentForms,
            physicalConsentForms,
            digitalLeadForms: leadAutoCount
        });
        saveFacilityStats();

        // Save to records
        jfaRecords.push(currentJFA);
        appendWeeklyFeedback(currentJFA);
        scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
        scheduleStorageWrite(STORAGE_KEYS.lastDbd, JSON.stringify(currentJFA));

        // Navigate to stats
        showToast('DBD submitted successfully.', 'success');
        openSuccessModal(currentJFA);
        triggerConfetti();
        if (sessionLockEnabled) {
            sessionLocked = true;
            scheduleStorageWrite(STORAGE_KEYS.sessionLocked, 'true');
        }
        logAudit('DBD submitted', `${currentJFA.name} • ${currentJFA.team} • total ${consentForms} (physical ${physicalConsentForms} + digital ${leadAutoCount})`);
        localStorage.removeItem(STORAGE_KEYS.dbdDraft);
        localStorage.removeItem(STORAGE_KEYS.currentJfa);
        form.reset();
        currentJFA = null;
        updateSummary();
        updateHeroSummary();
        updateResumeBanner();
        await syncCriticalCloudState('DBD');
        navigateToStats();
    });

    const draft = JSON.parse(localStorage.getItem(STORAGE_KEYS.dbdDraft));
    if (draft) {
        if (draft.productive) {
            const radio = document.querySelector(`input[name="productive"][value="${draft.productive}"]`);
            if (radio) radio.checked = true;
        }
        if (typeof draft.consentForms !== 'undefined') {
            setInputValue('consentForms', draft.consentForms);
        }
        if (draft.notes) {
            setInputValue('notes', draft.notes);
        }
    }
    if (consentInput) {
        consentInput.addEventListener('input', () => {
            if (!currentJFA?.name) return;
            const hint = document.getElementById('consentAutoHint');
            if (!hint) return;
            const leadAutoCount = getTodayLeadCountForName(currentJFA.name);
            const entered = parseInt(consentInput.value, 10);
            const safePhysical = Number.isNaN(entered) ? 0 : Math.max(0, entered);
            const total = safePhysical + leadAutoCount;
            hint.textContent = `Digital leads auto-added by system: ${leadAutoCount}. Physical: ${safePhysical}. Total consent forms: ${total}.`;
        });
    }
    syncConsentInputWithAutoCount();
}

// Navigation functions
async function navigateToRegister(edit = false) {
    if (!(await confirmLeaveIfDirty())) return;
    if (edit && sessionLocked) {
        showToast('Session is locked after DBD submission.', 'error');
        return;
    }
    goToPage('registration-page');
    isEditingRegistration = !!edit;
    if (isEditingRegistration && currentJFA) {
        const nameEl = document.getElementById('fullName');
        const phoneEl = document.getElementById('phoneNumber');
        const teamEl = document.getElementById('jfaTeam');
        if (nameEl) nameEl.value = currentJFA.name || '';
        if (phoneEl) phoneEl.value = currentJFA.phone || '';
        if (teamEl) teamEl.value = currentJFA.team || '';

        const planPlan = document.querySelector('input[name="facilityPlan"][value="PLAN"]');
        if (planPlan) planPlan.checked = true;
        const facilitySelection = document.getElementById('facilitySelection');
        if (facilitySelection) facilitySelection.style.display = 'block';
        const select = document.getElementById('selectedFacility');
        if (select && currentJFA.facility) {
            const filterInput = document.getElementById('facilityFilter');
            renderFacilityOptions(filterInput?.value || '');
            select.value = String(currentJFA.facility.id);
        }
        const customFields = document.getElementById('customFacilityFields');
        if (customFields) customFields.style.display = 'none';
        preAssignedFacilityId = null;
        renderRegisterDraftNotice('');
    } else if (!currentJFA) {
        applyRegisterDraft();
    }
}

function navigateToAssignment() {
    if (!currentJFA || !currentJFA.facility) {
        showToast('Please register first.', 'error');
        navigateToRegister();
        return;
    }
    // Display assignment details
    setElementText('assignmentDate', new Date().toLocaleDateString('en-ZA', {
        weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    }));
    setElementText('assignedFacilityName', currentJFA.facility.name);
    setElementText('facilityTypeDisplay', currentJFA.facility.type);
    setElementText('facilityAreaDisplay', currentJFA.facility.area);
    setElementText('facilityContactDisplay', currentJFA.facility.contact);
    setElementText('facilityPhoneDisplay', currentJFA.facility.phone);
    setElementText('yourTeamDisplay', currentJFA.team);
    renderAssignmentCompanions();
    renderAssignmentAppointmentReminders();

    goToPage('assignment-page');
}

function getAssignmentCompanionsForToday() {
    if (!currentJFA || !currentJFA.facility) return [];
    const today = todayKey();
    const currentName = normalizeJfaName(currentJFA.name || '');
    const currentFacilityName = normalizeFacilityName(currentJFA.facility.name || '');
    const currentFacilityId = Number(currentJFA.facility.id) || 0;
    const companions = jfaRecords
        .filter((record) => recordDateKey(record) === today)
        .filter((record) => normalizeJfaName(record?.name || '') !== currentName)
        .filter((record) => {
            const facility = record?.facility;
            if (!facility) return false;
            const recordFacilityId = Number(facility.id) || 0;
            if (currentFacilityId && recordFacilityId) return recordFacilityId === currentFacilityId;
            return normalizeFacilityName(facility.name || '') === currentFacilityName;
        })
        .map((record) => formatJfaName(record.name || ''))
        .filter(Boolean);
    return [...new Set(companions)].sort((a, b) => a.localeCompare(b));
}

function renderAssignmentCompanions() {
    const el = document.getElementById('assignmentCompanionsDisplay');
    if (!el) return;
    const companions = getAssignmentCompanionsForToday();
    if (!companions.length) {
        el.textContent = 'No other JFAs assigned yet.';
        return;
    }
    el.textContent = companions.join(', ');
}

function isUnderAutoAssignmentTarget(facility) {
    if (!facility) return false;
    const allocations = Number(facility.allocations) || 0;
    const target = Math.min(MIN_AUTO_ASSIGNMENT_GROUP_SIZE, Math.max(1, capacityFor(facility)));
    return allocations < target;
}

function pickAutoAssignedFacility(availableFacilities) {
    if (!Array.isArray(availableFacilities) || !availableFacilities.length) return null;
    const activeUnderTarget = availableFacilities.filter((facility) => {
        const allocations = Number(facility.allocations) || 0;
        return allocations > 0 && isUnderAutoAssignmentTarget(facility);
    });
    let pool = activeUnderTarget;
    if (!pool.length) {
        pool = availableFacilities.filter((facility) => (Number(facility.allocations) || 0) === 0);
    }
    if (!pool.length) {
        pool = availableFacilities.filter((facility) => isUnderAutoAssignmentTarget(facility));
    }
    if (!pool.length) {
        pool = availableFacilities;
    }
    const minAllocations = Math.min(...pool.map((facility) => Number(facility.allocations) || 0));
    const leastLoaded = pool.filter((facility) => (Number(facility.allocations) || 0) === minAllocations);
    return leastLoaded[Math.floor(Math.random() * leastLoaded.length)] || null;
}

function renderAssignmentAppointmentReminders() {
    const container = document.getElementById('assignmentAppointmentReminders');
    if (!container) return;
    if (!appUser) {
        container.innerHTML = `
            <h4>Appointment Reminders</h4>
            <p class="page-subtitle">Sign in to view your upcoming client appointments.</p>
        `;
        return;
    }
    const now = new Date();
    const today = todayKey();
    const upcoming = getUserAppointments(appUser)
        .map((item) => ({ ...item, dt: getAppointmentDateTime(item) }))
        .filter((item) => item.dt && item.dt >= now)
        .sort((a, b) => a.dt - b.dt)
        .slice(0, 5);
    const todays = upcoming.filter((item) => item.date === today);
    if (!upcoming.length) {
        container.innerHTML = `
            <h4>Appointment Reminders</h4>
            <p class="page-subtitle">No upcoming appointments found. Set one from <strong>Menu → Appointments</strong> or while submitting a lead.</p>
            <div class="menu-page-actions"><button class="action-btn secondary" type="button" onclick="openMenuPage('appointments')">Open Appointments</button></div>
        `;
        return;
    }
    container.innerHTML = `
        <h4>Appointment Reminders</h4>
        <p class="page-subtitle">Today: ${todays.length} upcoming appointment${todays.length === 1 ? '' : 's'}.</p>
        <div class="insight-list">
            ${upcoming.map((item) => {
                const diff = Math.max(0, Math.round((item.dt.getTime() - now.getTime()) / 60000));
                const soon = diff <= 60 ? 'danger' : '';
                return `<span class="insight-chip ${soon}">${escapeHtml(item.time || '—')} • ${escapeHtml(item.clientName || 'Client')} • LID ${escapeHtml(item.leadId || '—')} (${diff} min)</span>`;
            }).join('')}
        </div>
        <div class="menu-page-actions" style="margin-top:10px;">
            <button class="action-btn secondary" type="button" onclick="openMenuPage('appointments')">Manage Appointments</button>
        </div>
    `;
}

function navigateToDBD() {
    if (!currentJFA || !currentJFA.facility) {
        showToast('Please register first.', 'error');
        navigateToRegister();
        return;
    }
    setElementText('dbdFacilityName', currentJFA.facility.name);
    syncConsentInputWithAutoCount();
    goToPage('dbd-page');
}

function navigateToStats() {
    updateStatistics();
    updateHeroSummary();
    updateResumeBanner();
    goToPage('stats-page');
}

function navigateToArchives() {
    renderArchives();
    goToPage('archives-page');
}

async function resetToLanding() {
    if (!(await confirmLeaveIfDirty())) return;
    currentJFA = null;
    const jfaFormEl = document.getElementById('jfaForm');
    const dbdFormEl = document.getElementById('dbdForm');
    if (jfaFormEl) jfaFormEl.reset();
    if (dbdFormEl) dbdFormEl.reset();
    updateResumeBanner();
    scheduleStorageWrite(STORAGE_KEYS.lastPage, 'landing-page');
    goToPage('landing-page');
}

function openResetModal() {
    const modal = document.getElementById('reset-modal');
    const input = document.getElementById('resetDataConfirmInput');
    const error = document.getElementById('resetDataConfirmError');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
    if (input) input.value = '';
    if (error) {
        error.textContent = '';
        error.style.display = 'none';
    }
    if (input) setTimeout(() => input.focus(), 30);
}

function closeResetModal() {
    const modal = document.getElementById('reset-modal');
    const error = document.getElementById('resetDataConfirmError');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
    if (error) {
        error.textContent = '';
        error.style.display = 'none';
    }
}

function confirmResetAllData() {
    closeResetModal();
    resetAllData();
}

function confirmResetAllDataFromModal() {
    const input = document.getElementById('resetDataConfirmInput');
    const error = document.getElementById('resetDataConfirmError');
    if ((input?.value || '').trim() !== 'DELETE ALL DATA') {
        if (error) {
            error.textContent = 'Type DELETE ALL DATA exactly to continue.';
            error.style.display = 'block';
        }
        return;
    }
    closeResetModal();
    resetAllData();
}

function openSuccessModal(record, options = {}) {
    const modal = document.getElementById('success-modal');
    if (!modal) return;
    const title = document.getElementById('successModalTitle');
    const body = document.getElementById('successModalBody');
    const primaryBtn = document.getElementById('successModalPrimaryBtn');
    if (title) {
        title.textContent = options.title || 'DBD Submitted';
    }
    if (body) {
        if (typeof options.body === 'string' && options.body.trim()) {
            body.textContent = options.body;
        } else if (record) {
            body.textContent = `${record.name} submitted ${record.consentForms || 0} forms at ${record.facility?.name ?? ''}.`;
        } else {
            body.textContent = 'Your submission has been recorded.';
        }
    }
    successModalPrimaryAction = typeof options.primaryAction === 'function' ? options.primaryAction : null;
    if (primaryBtn) {
        primaryBtn.textContent = options.primaryLabel || 'View Stats';
        primaryBtn.style.display = options.hidePrimary ? 'none' : '';
    }
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
}

function closeSuccessModal() {
    const modal = document.getElementById('success-modal');
    if (!modal) return;
    successModalPrimaryAction = null;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
}

function openBenExportModal(message) {
    const modal = document.getElementById('ben-export-modal');
    const body = document.getElementById('benExportMessage');
    if (!modal) return;
    if (body) {
        body.textContent = String(message || 'Ben System export completed.');
    }
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
}

function closeBenExportModal() {
    const modal = document.getElementById('ben-export-modal');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
}

function handleSuccessModalPrimary() {
    if (typeof successModalPrimaryAction === 'function') {
        const action = successModalPrimaryAction;
        closeSuccessModal();
        try {
            action();
        } catch (_) {
            // ignore callback failures
        }
        return;
    }
    viewStatsFromModal();
}

function viewStatsFromModal() {
    closeSuccessModal();
    navigateToStats();
}

function saveResetTime() {
    const input = document.getElementById('resetTime');
    if (!input) return;
    const value = '00:00';
    scheduleStorageWrite(STORAGE_KEYS.resetTime, value);
    input.value = value;
    showToast('Reset time is fixed at 00:00.', 'success');
    checkDailyReset();
}

function loadResetTime() {
    const input = document.getElementById('resetTime');
    if (!input) return;
    input.value = '00:00';
    input.disabled = true;
}

function canExportFromCurrentScope() {
    return adminRole === 'ADMIN' || hasAppPermission('forms');
}

function filterJfaRecordsForExport(records) {
    if (!Array.isArray(records)) return [];
    return records.filter((record) => !isTeamLeaderName(record?.name, record?.team || ''));
}

function exportStatsCsv() {
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export stats.', 'error');
        return;
    }
    const records = filterJfaRecordsForExport(getScopedRecords());
    const date = new Date().toISOString().slice(0, 10);
    exportRecordsCsv(records, `jfa-stats-${date}.csv`);
    logAudit('Exported stats', `Scope: ${adminRole === 'TEAM' ? adminTeam : adminRole} • Rows: ${records.length}`);
    logExportHistory('Stats Export', records.length);
}

function exportStatsPdf() {
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export stats.', 'error');
        return;
    }
    const records = filterJfaRecordsForExport(getScopedRecords());
    const date = new Date().toISOString().slice(0, 10);
    exportRecordsPdf(records, `jfa-stats-${date}.pdf`);
    logAudit('Exported stats PDF', `Scope: ${adminRole === 'TEAM' ? adminTeam : adminRole} • Rows: ${records.length}`);
    logExportHistory('Stats PDF Export', records.length);
}

function exportDbdsCsv() {
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export DBD records.', 'error');
        return;
    }
    const scoped = filterJfaRecordsForExport(getScopedRecords());
    if (!scoped.length) {
        showToast('No DBD data to export yet.', 'error');
        return;
    }
    const date = new Date().toISOString().slice(0, 10);
    const headers = [
        'Name',
        'Team',
        'Facility',
        'Facility Contact',
        'Facility Area',
        'Productive',
        'Consent Forms',
        'Notes',
        'Timestamp'
    ];
    const rows = scoped.map((record) => [
        record.name,
        record.team,
        record.facility?.name ?? '',
        record.facility?.contact ?? '',
        record.facility?.area ?? '',
        record.productive ?? '',
        record.consentForms ?? 0,
        record.notes ?? '',
        record.timestamp ?? ''
    ]);
    exportCsvWithHeaders(headers, rows, `jfa-dbd-${date}.csv`);
    logAudit('Exported DBD records', `Scope: ${adminRole === 'TEAM' ? adminTeam : adminRole} • Rows: ${rows.length}`);
    logExportHistory('DBD Export', rows.length);
}

function exportDbdsPdf() {
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export DBD records.', 'error');
        return;
    }
    const scoped = filterJfaRecordsForExport(getScopedRecords());
    if (!scoped.length) {
        showToast('No DBD data to export yet.', 'error');
        return;
    }
    const date = new Date().toISOString().slice(0, 10);
    const headers = [
        'Name',
        'Team',
        'Facility',
        'Facility Contact',
        'Facility Area',
        'Productive',
        'Consent Forms',
        'Notes',
        'Timestamp'
    ];
    const rows = scoped.map((record) => [
        record.name,
        record.team,
        record.facility?.name ?? '',
        record.facility?.contact ?? '',
        record.facility?.area ?? '',
        record.productive ?? '',
        record.consentForms ?? 0,
        record.notes ?? '',
        record.timestamp ?? ''
    ]);
    exportPdfWithHeaders(headers, rows, `jfa-dbd-${date}.pdf`, 'DBD Records');
    logAudit('Exported DBD PDF', `Scope: ${adminRole === 'TEAM' ? adminTeam : adminRole} • Rows: ${rows.length}`);
    logExportHistory('DBD PDF Export', rows.length);
}

function getDateRange(rangeKey) {
    const now = new Date();
    const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
    if (rangeKey === 'today') {
        const start = startOfDay(now);
        const end = new Date(start);
        end.setHours(23, 59, 59, 999);
        return { start, end };
    }
    if (rangeKey === 'this-week') {
        const start = getStartOfWeek(now);
        const end = new Date(now);
        return { start, end };
    }
    if (rangeKey === 'last-week') {
        const end = new Date(getStartOfWeek(now));
        end.setDate(end.getDate() - 1);
        end.setHours(23, 59, 59, 999);
        const start = getStartOfWeek(end);
        return { start, end };
    }
    if (rangeKey === 'this-month') {
        const start = getStartOfMonth(now);
        const end = new Date(now);
        return { start, end };
    }
    return null;
}

function exportRangeCsv() {
    const select = document.getElementById('exportRange');
    const startInput = document.getElementById('exportStart');
    const endInput = document.getElementById('exportEnd');
    if (!select) return;
    let range = getDateRange(select.value);
    if (select.value === 'custom') {
        if (!startInput?.value || !endInput?.value) {
            showToast('Select a start and end date.', 'error');
            return;
        }
        const start = new Date(startInput.value);
        const end = new Date(endInput.value);
        end.setHours(23, 59, 59, 999);
        range = { start, end };
    }
    if (!range) return;
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export records.', 'error');
        return;
    }
    const records = filterJfaRecordsForExport([
        ...getArchiveRangeRecords(range.start, range.end).filter(recordMatchesScope),
        ...jfaRecords.filter((r) => {
            if (!r.timestamp) return false;
            const d = new Date(r.timestamp);
            if (d < range.start || d > range.end) return false;
            return recordMatchesScope(r);
        })
    ]);
                        if (!records.length) {
                            showToast('No data for this range.', 'error');
                            return;
                        }
    exportRecordsCsv(records, `jfa-range-${dateKeyLocal(range.start)}-to-${dateKeyLocal(range.end)}.csv`);
    logAudit('Exported range records', `Scope: ${adminRole === 'TEAM' ? adminTeam : adminRole} • Rows: ${records.length}`);
    logExportHistory('Range Export', records.length);
}

function exportTeamCsv(team) {
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export team records.', 'error');
        return;
    }
    if (adminRole === 'TEAM' && adminTeam && adminTeam !== team) {
        showToast('You can only export your own team records.', 'error');
        return;
    }
    if (adminRole === 'PERSONAL') {
        showToast('Select team/admin scope to export team records.', 'error');
        return;
    }
    const records = filterJfaRecordsForExport(jfaRecords.filter((r) => r.team === team && recordMatchesScope(r)));
    if (!records.length) {
        showToast(`No records for ${team}.`, 'error');
        return;
    }
    exportRecordsCsv(records, `jfa-${team.replace(/\s+/g, '-').toLowerCase()}-${todayKey()}.csv`);
    logAudit('Exported team records', `Team: ${team} • Rows: ${records.length}`);
    logExportHistory(`Team Export: ${team}`, records.length);
}

function showCompleteDaySummary() {
    const panel = document.getElementById('completeDayPanel');
    const summaryEl = document.getElementById('completeSummary');
    const graphEl = document.getElementById('completeGraph');
    const calendarHeader = document.getElementById('calendarHeader');
    const calendarGrid = document.getElementById('calendarGrid');
    const messageEl = document.getElementById('completeMessage');
    if (!panel || !summaryEl || !graphEl || !calendarGrid || !calendarHeader || !messageEl) return;

    const active = currentJFA || JSON.parse(localStorage.getItem(STORAGE_KEYS.lastDbd) || 'null');
    if (!active || !active.name) {
        showToast('No JFA found for monthly summary. Submit a DBD first.', 'error');
        return;
    }
    const name = active.name;
    const team = active.team;

    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    monthEnd.setHours(23, 59, 59, 999);

    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, monthEnd),
        ...jfaRecords.filter((r) => {
            if (!r.timestamp) return false;
            const d = new Date(r.timestamp);
            return d >= monthStart && d <= monthEnd;
        })
    ].filter((r) => r.name === name && (!team || r.team === team));
    monthRecords.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const totalForms = monthRecords.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const daysPresent = new Set(monthRecords.map((r) => (r.timestamp || '').slice(0, 10))).size;

    const leaderboardTotals = new Map();
    filterJfaRecordsForExport([
        ...getArchiveRangeRecords(monthStart, monthEnd),
        ...jfaRecords.filter((r) => r.timestamp)
    ]).forEach((r) => {
        if (!r.name) return;
        const key = r.name;
        leaderboardTotals.set(key, (leaderboardTotals.get(key) || 0) + (r.consentForms || 0));
    });
    const ranked = [...leaderboardTotals.entries()].sort((a, b) => b[1] - a[1]);
    const rankIndex = ranked.findIndex(([n]) => n === name);
    const rank = rankIndex === -1 ? '—' : `${rankIndex + 1} / ${ranked.length}`;

    summaryEl.innerHTML = `
        <div class="summary-item"><span class="summary-value">${totalForms}</span><span class="summary-label">Forms This Month</span></div>
        <div class="summary-item"><span class="summary-value">${daysPresent}</span><span class="summary-label">Days Present</span></div>
        <div class="summary-item"><span class="summary-value">${rank}</span><span class="summary-label">Leaderboard Rank</span></div>
    `;

    // Graph (daily forms)
    const daysInMonth = monthEnd.getDate();
    const dailyTotals = new Array(daysInMonth).fill(0);
    monthRecords.forEach((r) => {
        const d = new Date(r.timestamp);
        const idx = d.getDate() - 1;
        dailyTotals[idx] += r.consentForms || 0;
    });
    const max = Math.max(1, ...dailyTotals);
    graphEl.innerHTML = dailyTotals
        .map((v) => `<div class="complete-bar" style="height:${Math.max(CONFIG.MIN_BAR_HEIGHT, Math.round((v / max) * 100))}%"></div>`)
        .join('');

    // Calendar
    calendarHeader.textContent = `${now.toLocaleString('en-ZA', { month: 'long' })} ${now.getFullYear()}`;
    calendarGrid.innerHTML = '';
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).getDay();
    for (let i = 0; i < firstDay; i++) {
        const empty = document.createElement('div');
        empty.className = 'calendar-day absent';
        calendarGrid.appendChild(empty);
    }

    const byDay = new Map();
    monthRecords.forEach((r) => {
        const key = new Date(r.timestamp).getDate();
        const total = byDay.get(key) || { forms: 0, productive: 'NO' };
        total.forms += r.consentForms || 0;
        if (r.productive === 'YES') total.productive = 'YES';
        byDay.set(key, total);
    });
    const maxDay = [...byDay.entries()].sort((a, b) => b[1].forms - a[1].forms)[0];
    const minDay = [...byDay.entries()].sort((a, b) => a[1].forms - b[1].forms)[0];
    const mostDay = maxDay ? maxDay[0] : null;
    const leastDay = minDay ? minDay[0] : null;

    for (let day = 1; day <= daysInMonth; day++) {
        const cell = document.createElement('div');
        cell.className = 'calendar-day';
        cell.textContent = day;
        const info = byDay.get(day);
        const date = new Date(now.getFullYear(), now.getMonth(), day);
        const isWeekend = date.getDay() === 0 || date.getDay() === 6;
        if (info) {
            if (info.productive === 'YES' && info.forms >= 2) {
                cell.classList.add('present');
            } else if (info.productive === 'YES') {
                cell.classList.add('content');
            } else {
                cell.classList.add('not-productive');
            }
            if (mostDay === day) cell.classList.add('most');
            if (leastDay === day) cell.classList.add('least');
        } else if (isWeekend) {
            cell.classList.add('weekend');
        } else if (date <= now) {
            cell.classList.add('absent');
        }
        calendarGrid.appendChild(cell);
    }

    // Message
    const lastRecord = monthRecords[monthRecords.length - 1];
    if (lastRecord && lastRecord.productive === 'YES' && (lastRecord.consentForms || 0) >= 2) {
        messageEl.textContent = `GoodBye ${name}! Great job today—productive and on target. Safe travels back.`;
    } else if (lastRecord && lastRecord.productive === 'YES') {
        messageEl.textContent = `GoodBye ${name}. Not bad, but you can do better tomorrow. Safe travels back.`;
    } else {
        messageEl.textContent = `GoodBye ${name}. Pull your socks up or stay home. Safe travels back.`;
    }

    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function downloadCurrentDbd() {
    if (!currentJFA) {
        showToast('Please register first.', 'error');
        return;
    }
    const productive = document.querySelector('input[name=\"productive\"]:checked')?.value || '';
    const consentForms = document.getElementById('consentForms')?.value || '';
    const notes = document.getElementById('notes')?.value || '';
    const headers = ['Name', 'Team', 'Facility', 'Facility Contact', 'Facility Area', 'Productive', 'Consent Forms', 'Notes', 'Timestamp'];
    const rows = [[
        currentJFA.name,
        currentJFA.team,
        currentJFA.facility?.name ?? '',
        currentJFA.facility?.contact ?? '',
        currentJFA.facility?.area ?? '',
        productive || currentJFA.productive || '',
        consentForms || currentJFA.consentForms || 0,
        notes || currentJFA.notes || '',
        currentJFA.timestamp || new Date().toISOString()
    ]];
    exportCsvWithHeaders(headers, rows, `dbd-${currentJFA.name || 'jfa'}.csv`);
}

function saveDbdDraft() {
    const productive = document.querySelector('input[name="productive"]:checked')?.value || '';
    const consentForms = document.getElementById('consentForms')?.value || '';
    const notes = document.getElementById('notes')?.value || '';
    const draft = { productive, consentForms, notes };
    scheduleStorageWrite(STORAGE_KEYS.dbdDraft, JSON.stringify(draft));
    showToast('Draft saved.', 'success');
}

function editLastDbd() {
    const last = JSON.parse(localStorage.getItem(STORAGE_KEYS.lastDbd) || 'null');
    if (!last) {
        showToast('No previous DBD to edit.', 'error');
        return;
    }
    if (last.productive) {
        const radio = document.querySelector(`input[name="productive"][value="${last.productive}"]`);
        if (radio) radio.checked = true;
    }
    setInputValue('consentForms', last.consentForms || 0);
    setInputValue('notes', last.notes || '');
    syncConsentInputWithAutoCount();
    showToast('Loaded last DBD into the form.', 'success');
}

async function confirmLeaveIfDirty() {
    if (!hasUnsavedChanges()) return true;
    return openAppConfirmModal({
        title: 'Unsaved Changes',
        message: 'You have unsaved DBD changes. Leave this page without saving?',
        confirmText: 'Leave',
        cancelText: 'Stay'
    });
}

function toggleTheme() {
    document.body.classList.add('theme-transition');
    const isDark = document.body.classList.toggle('dark');
    scheduleStorageWrite(STORAGE_KEYS.theme, isDark ? 'dark' : 'light');
    setTimeout(() => document.body.classList.remove('theme-transition'), CONFIG.THEME_TRANSITION);
}

function toggleSidebar(forceClose = false) {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sidebar || !overlay) return;
    const isOpen = sidebar.classList.contains('is-open');
    if (forceClose || isOpen) {
        sidebar.classList.remove('is-open');
        overlay.classList.remove('is-open');
        document.body.classList.remove('sidebar-open');
        closeLeadsMenu();
    } else {
        closeQuickActionsMenu();
        sidebar.classList.add('is-open');
        overlay.classList.add('is-open');
        document.body.classList.add('sidebar-open');
    }
}

function toggleLeadsMenu(forceClose = false) {
    const submenu = document.getElementById('leadsSubmenu');
    if (!submenu) return;
    if (!forceClose && !hasAppPermission('leads')) {
        showToast('You do not have access to Leads.', 'error');
        return;
    }
    if (forceClose) {
        submenu.classList.remove('is-open');
        return;
    }
    submenu.classList.toggle('is-open');
}

function closeLeadsMenu() {
    const submenu = document.getElementById('leadsSubmenu');
    if (submenu) submenu.classList.remove('is-open');
}

function updateSidebarMenuState(activePage = '') {
    const buttons = document.querySelectorAll('.sidebar [data-menu]');
    buttons.forEach((button) => {
        const menu = button.getAttribute('data-menu') || '';
        const isActive = Boolean(activePage) && menu === activePage;
        button.classList.toggle('is-active', isActive);
        if (isActive) {
            button.setAttribute('aria-current', 'page');
        } else {
            button.removeAttribute('aria-current');
        }
    });
}

function updatePermissionDrivenUi() {
    const menuPermissionMap = {
        admin: 'admin',
        learning: 'learning',
        forms: 'forms',
        leads: 'leads',
        payments: 'leads',
        benSystem: 'leads',
        appointments: 'leads',
        settings: 'settings'
    };
    Object.entries(menuPermissionMap).forEach(([menu, permissionKey]) => {
        const button = document.querySelector(`.sidebar [data-menu="${menu}"]`);
        if (!button) return;
        const allowed = hasAppPermission(permissionKey);
        const container = button.closest('.sidebar-section') || button.closest('.sidebar-footer') || button;
        if (container) {
            container.style.display = allowed ? '' : 'none';
        }
        button.disabled = !allowed;
    });
    const openLeadsBtn = document.querySelector(".hero-secondary-cta[onclick*=\"openMenuPage('leads')\"]");
    if (openLeadsBtn) {
        openLeadsBtn.style.display = hasAppPermission('leads') ? 'inline-flex' : 'none';
    }
    if (!hasAppPermission('leads')) {
        closeLeadsMenu();
    }
    if (activeMenuPage && !canAccessMenuPage(activeMenuPage)) {
        closeMenuPage();
    }
    const adminHomeBtn = document.getElementById('adminHomeBtn');
    if (adminHomeBtn) {
        const canAdminHome = adminRole === 'ADMIN' && hasAppPermission('admin');
        adminHomeBtn.style.display = canAdminHome ? '' : 'none';
    }
    const adminOnlyControls = document.querySelectorAll('.admin-only-control');
    adminOnlyControls.forEach((el) => {
        if (!(el instanceof HTMLElement)) return;
        el.style.display = adminRole === 'ADMIN' ? '' : 'none';
    });
    const notifyTeamBtn = document.getElementById('notifyTeamBtn');
    const notifyAllBtn = document.getElementById('notifyAllBtn');
    const canNotifyTeam = adminRole === 'TEAM' || adminRole === 'ADMIN';
    const canNotifyAll = adminRole === 'ADMIN';
    if (notifyTeamBtn) {
        notifyTeamBtn.style.display = canNotifyTeam ? '' : 'none';
        if (canNotifyTeam) {
            notifyTeamBtn.onclick = () => openInlineNotificationComposer('adminNotificationInline', '');
        }
    }
    if (notifyAllBtn) notifyAllBtn.style.display = canNotifyAll ? '' : 'none';
}

function openLeadsFromMenu(tab = 'submit') {
    closeLeadsMenu();
    openMenuPage('leads');
    openLeadsTab(tab);
}

function safeMenuPageRender(pageKey, pageId, renderFn) {
    try {
        renderFn();
    } catch (error) {
        const container = document.getElementById(pageId);
        if (container) {
            container.innerHTML = `
                <div class="insight-card">
                    <h4>Section Error</h4>
                    <p class="menu-page-note">This section failed to load. Please refresh and try again.</p>
                </div>
            `;
        }
        console.error(`Menu page render failed (${pageKey}):`, error);
        showToast(`Could not load ${pageKey} section.`, 'error');
    }
}

function openMenuPage(page, pushHistory = true, skipAdminGate = false) {
    if (typeof closeNotificationDropdown === 'function') {
        closeNotificationDropdown();
    }
    renderQuickActionsMenu();
    closeQuickActionsMenu();
    if (page === 'admin' && adminRole === 'ADMIN' && !skipAdminGate && !isAdminStandaloneActive()) {
        navigateAdminHome();
        return;
    }
    if (page === 'admin' && !skipAdminGate && !requireAdminMenuAccess(() => openMenuPage('admin', pushHistory, true))) {
        return;
    }
    if (!canAccessMenuPage(page)) {
        showToast('You do not have access to that section.', 'error');
        return;
    }
    const overlay = document.getElementById('menuPageOverlay');
    const pages = {
        admin: document.getElementById('adminPage'),
        learning: document.getElementById('learningPage'),
        forms: document.getElementById('formsPage'),
        leads: document.getElementById('leadsPage'),
        payments: document.getElementById('paymentsPage'),
        benSystem: document.getElementById('benSystemPage'),
        appointments: document.getElementById('appointmentsPage'),
        teamDetail: document.getElementById('teamDetailPage'),
        learningDetail: document.getElementById('learningDetailPage'),
        archivedJfas: document.getElementById('archivedJfaPage'),
        settings: document.getElementById('settingsPage')
    };
    Object.values(pages).forEach((node) => {
        if (!node) return;
        node.classList.remove('is-open');
        node.setAttribute('aria-hidden', 'true');
    });
    const target = pages[page];
    if (!target || !overlay) {
        showToast('That section is unavailable right now.', 'error');
        return;
    }
    if (pushHistory && activeMenuPage && activeMenuPage !== page) {
        menuPageHistory.push(activeMenuPage);
    }
    activeMenuPage = page;
    toggleSidebar(true);
    overlay.classList.add('is-open');
    target.classList.add('is-open');
    target.setAttribute('aria-hidden', 'false');
    target.classList.remove('is-scrolled');
    target.scrollTop = 0;
    target.classList.remove('menu-page-enter');
    void target.offsetWidth;
    target.classList.add('menu-page-enter');
    updateSidebarMenuState(page);
    setDataFocusMode(lastActivePageId, page);
    const primaryAction = target.querySelector('button, input, select, textarea, a');
    if (primaryAction) {
        setTimeout(() => primaryAction.focus(), 90);
    }
    updateMenuPageTopButton();
    updateMenuScopeChips(page);
    if (page === 'learning') {
        updateLearningResumeButton();
        updateLearningBookmarkButton();
        renderLearningSearchResults();
        if (!learningFiltersBound) {
            const filterInputs = document.querySelectorAll('.learning-filter');
            filterInputs.forEach((input) => {
                input.addEventListener('change', () => {
                    if (learningSearchTerm) {
                        renderLearningSearchResults();
                    }
                });
            });
            learningFiltersBound = true;
        }
    }
    if (page === 'forms') {
        safeMenuPageRender('forms', 'formsList', () => renderFormsLibrary());
    }
    if (page === 'admin') {
        safeMenuPageRender('admin', 'adminTeamPortalButtons', () => {
            renderTeamPortalButtons();
            adminFacilityDirectoryOpen = false;
            renderAdminInsights();
            renderAdminTeamDetails();
            updateFacilityDirectoryToggleButton();
            renderFacilityDirectory();
        });
    }
    if (page === 'archivedJfas') {
        safeMenuPageRender('archived JFAs', 'archivedJfaList', () => renderArchivedJfas());
    }
    if (page === 'leads') {
        safeMenuPageRender('leads', 'leadsPage', () => openLeadsTab('submit'));
    }
    if (page === 'payments') {
        safeMenuPageRender('payments', 'paymentsBody', () => setPaymentsTab('pending'));
    }
    if (page === 'benSystem') {
        safeMenuPageRender('Ben System', 'benSystemBody', () => renderBenSystemPage());
    }
    if (page === 'appointments') {
        safeMenuPageRender('appointments', 'appointmentsBody', () => renderAppointmentsPage());
    }
    if (page === 'settings') {
        safeMenuPageRender('settings', 'settingsBody', () => renderSettingsPage());
    }
    queueUiRefresh();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function goBackMenuPage() {
    if (menuPageHistory.length > 0) {
        const previous = menuPageHistory.pop();
        openMenuPage(previous, false);
        return;
    }
    closeMenuPage();
}

function closeMenuPage(clearHistory = true) {
    const overlay = document.getElementById('menuPageOverlay');
    const pages = document.querySelectorAll('.menu-page.is-open');
    if (overlay) overlay.classList.remove('is-open');
    renderQuickActionsMenu();
    closeQuickActionsMenu();
    pages.forEach((page) => {
        page.classList.remove('is-open');
        page.setAttribute('aria-hidden', 'true');
    });
    if (clearHistory) {
        activeMenuPage = '';
        menuPageHistory.length = 0;
    }
    updateSidebarMenuState('');
    setDataFocusMode(document.querySelector('.page.active')?.id || lastActivePageId, '');
    updateMenuPageTopButton(true);
    queueUiRefresh();
}

function setAdminRole(role, team, triggerEvent = null) {
    if ((role === 'ADMIN' || role === 'TEAM') && !requireAdminAccess(() => setAdminRole(role, team), triggerEvent)) {
        return;
    }
    adminRole = role || 'PERSONAL';
    adminTeam = team || '';
    persistAdminScope();
    const note = document.getElementById('adminScopeNote');
    if (note) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
        note.textContent = `Scope: ${label || 'Personal'}`;
    }
    updateMenuScopeChips('admin');
    renderAdminInsights();
    renderAdminTeamDetails();
    renderFacilityDirectory();
    updateStatistics();
    updateSummary();
    goToPage('stats-page');
}

function openTeamDetailPage(teamName, bypassAllGate = false, triggerEvent = null) {
    if (teamName === 'ALL') {
        navigateAdminHome();
        return;
    }
    if (!bypassAllGate && teamName !== 'ALL') {
        const adminPageOpen = document.getElementById('adminPage')?.classList.contains('is-open');
        if (adminPageOpen) {
            openTeamAuthInline(teamName);
        } else {
            openTeamAuthModal(teamName, triggerEvent);
        }
        return;
    }
    if (!requireAdminAccess(() => openTeamDetailPage(teamName, bypassAllGate), triggerEvent)) {
        return;
    }
    if (teamName === 'ALL') {
        adminRole = 'ADMIN';
        adminTeam = '';
    } else {
        adminRole = 'TEAM';
        adminTeam = teamName;
    }
    persistAdminScope();
    const note = document.getElementById('adminScopeNote');
    if (note) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminTeam;
        note.textContent = `Scope: ${label || 'Personal'}`;
    }
    if (teamName === 'ALL') {
        adminFacilityDirectoryOpen = false;
        adminMasterTab = 'leads';
        updateMenuScopeChips('admin');
        renderAdminInsights();
        renderAdminTeamDetails();
        renderAdminMasterLogger();
        updateFacilityDirectoryToggleButton();
        renderFacilityDirectory();
        openMenuPage('admin');
        return;
    }
    updateMenuScopeChips('teamDetail');
    renderTeamDetailPage(teamName);
    openMenuPage('teamDetail');
}

function renderTeamDetailPage(teamName) {
    const titleEl = document.getElementById('teamDetailTitle');
    const scopeEl = document.getElementById('teamDetailScope');
    const container = document.getElementById('teamDetailContent');
    const inline = document.getElementById('teamDetailInlineDetail');
    if (!titleEl || !scopeEl || !container) return;
    const label = teamName === 'ALL' ? 'Admin (All Teams)' : teamName;
    titleEl.textContent = `${label} — Full Detail`;
    scopeEl.innerHTML = `<span class="scope-badge ${teamName === 'ALL' ? 'admin' : 'team'}">Scope: ${label}</span>`;
    updateMenuScopeChips('teamDetail');
    const notifyBtn = document.getElementById('teamSendNotificationBtn');
    const canSendTeamNotification = adminRole === 'TEAM' && Boolean(adminTeam);
    const notifyTargetTeam = adminTeam || teamName || '';
    if (notifyBtn) {
        notifyBtn.style.display = canSendTeamNotification ? '' : 'none';
        notifyBtn.onclick = canSendTeamNotification
            ? () => openInlineNotificationComposer('teamNotificationInline', notifyTargetTeam)
            : null;
    }
    const roster = buildTeamRoster(teamName);
    if (!roster.length) {
        const settingsPanel = teamSettingsOpen ? renderTeamLeaderSettingsPanel([], teamName) : '';
        const noRosterNotifyCard = canSendTeamNotification
            ? `
            <div class="insight-card">
                <h4>Team Notifications</h4>
                <p class="page-subtitle">Send updates to ${escapeHtml(notifyTargetTeam)} members only.</p>
                <div class="menu-page-actions">
                    <button class="action-btn secondary" type="button" onclick="openInlineNotificationComposer('teamNotificationInline', '${escapeHtml(notifyTargetTeam)}')">Send Notification to Team</button>
                </div>
            </div>
            `
            : '';
        container.innerHTML = `
            ${noRosterNotifyCard}
            ${settingsPanel}
            <p class="menu-page-note">No records available for ${escapeHtml(teamName)} yet.</p>
        `;
        if (inline) inline.innerHTML = '';
        activeInlineDetail.team = null;
        return;
    }
    if (inline) inline.innerHTML = '';
    activeInlineDetail.team = null;

    const totalFormsToday = roster.reduce((sum, entry) => sum + (entry.formsToday || 0), 0);
    const totalFormsMonth = roster.reduce((sum, entry) => sum + (entry.formsMonth || 0), 0);
    const totalLeadsToday = roster.reduce((sum, entry) => sum + (entry.leadsToday || 0), 0);
    const totalLeadsMonth = roster.reduce((sum, entry) => sum + (entry.leadsMonth || 0), 0);
    const presentCount = roster.filter((entry) => entry.presentToday).length;
    const riskCases = roster.filter((entry) => entry.needsAssistance);
    const jfaRoster = roster.filter((entry) => !entry.isTeamLeader);
    const teamDailyTarget = jfaRoster.length * CONFIG.DAILY_TARGET;
    const jfaFormsToday = jfaRoster.reduce((sum, entry) => sum + (entry.formsToday || 0), 0);
    const teamTargetGap = Math.max(0, teamDailyTarget - jfaFormsToday);
    const topJfa = [...jfaRoster].sort((a, b) => b.formsMonth - a.formsMonth)[0]
        || [...roster].sort((a, b) => b.formsMonth - a.formsMonth)[0];

    const registerRows = roster.map((entry) => {
        const statusLabel = entry.presentToday ? 'Present' : 'Absent';
        const riskLabel = entry.isTeamLeader
            ? (teamTargetGap > 0 ? `Team target behind by ${teamTargetGap}` : 'Team on target')
            : (entry.needsAssistance ? 'Needs urgent assistance' : 'Stable');
        return `
            <tr class="${entry.presentToday ? 'is-present' : 'is-absent'}" onclick="openAdminJfaDetail('${escapeHtml(entry.name)}','team')">
                <td><strong>${escapeHtml(entry.name)}</strong></td>
                <td>${statusLabel}</td>
                <td>${entry.leadsToday}</td>
                <td>${entry.formsToday}</td>
                <td>${entry.formsMonth}</td>
                <td><span class="admin-jfa-status ${entry.performanceCode}">${entry.performanceLabel}</span></td>
                <td>${entry.underStreak}</td>
                <td>${riskLabel}</td>
            </tr>
        `;
    }).join('');
    const riskCards = riskCases.length
        ? riskCases.map((entry) => `
            <button class="insight-chip danger" type="button" onclick="openTeamRiskJfa('${escapeHtml(entry.name)}')">
                ${escapeHtml(entry.name)}: ${escapeHtml(entry.riskMessage)} ${entry.openInterventions ? `(Open cases: ${entry.openInterventions})` : '(No intervention logged yet)'}
            </button>
        `).join('')
        : `<span class="insight-chip">${teamTargetGap > 0 ? `Team target behind by ${teamTargetGap} forms today.` : 'No critical risk alerts today.'}</span>`;

    const settingsPanel = teamSettingsOpen ? renderTeamLeaderSettingsPanel(roster, teamName) : '';
    const recentTeamNotes = getRecentSentTeamNotifications(notifyTargetTeam, 5);
    const recentTeamNotesHtml = recentTeamNotes.length
        ? `
            <div class="mini-table" style="margin-top:10px;">
                <table>
                    <thead>
                        <tr>
                            <th>When</th>
                            <th>Title</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${recentTeamNotes.map((note) => `
                            <tr>
                                <td>${note.createdAt ? new Date(note.createdAt).toLocaleString('en-ZA') : '—'}</td>
                                <td>${escapeHtml(note.title || 'Team Update')}</td>
                                <td>${escapeHtml(note.message || '—')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `
        : `<p class="page-subtitle" style="margin-top:10px;">No notifications sent by you yet.</p>`;
    const teamNotifyCard = canSendTeamNotification
        ? `
        <div class="insight-card">
            <h4>Team Notifications</h4>
            <p class="page-subtitle">Send updates to ${escapeHtml(notifyTargetTeam)} members only.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="openInlineNotificationComposer('teamNotificationInline', '${escapeHtml(notifyTargetTeam)}')">Send Notification to Team</button>
            </div>
            ${recentTeamNotesHtml}
        </div>
        `
        : '';

    container.innerHTML = `
        <div class="insight-card">
            <h4>Team Overview (${escapeHtml(teamName)})</h4>
            <div class="insight-list">
                <span class="insight-chip">Present Today: ${presentCount}/${roster.length}</span>
                <span class="insight-chip">Leads Today: ${totalLeadsToday}</span>
                <span class="insight-chip">Forms Today: ${totalFormsToday}</span>
                <span class="insight-chip">Leads Month: ${totalLeadsMonth}</span>
                <span class="insight-chip">Forms Month: ${totalFormsMonth}</span>
                <span class="insight-chip">Top JFA: ${escapeHtml(topJfa?.name || '—')} (${topJfa?.formsMonth || 0})</span>
            </div>
        </div>
        ${teamNotifyCard}
        ${settingsPanel}
        <div class="insight-card">
            <h4>Critical Risk Alerts</h4>
            <div class="insight-list">
                ${riskCards}
            </div>
        </div>
        <div class="insight-card">
            <h4>Live Team Register (Team-only)</h4>
            <p class="page-subtitle">Click a JFA row to view full profile, leads, consent forms, performance and support notes.</p>
            <div class="mini-table">
                <table>
                    <thead>
                        <tr>
                            <th>JFA</th>
                            <th>Status</th>
                            <th>Leads Today</th>
                            <th>Forms Today</th>
                            <th>Forms Month</th>
                            <th>Performance</th>
                            <th>Under Streak</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>${registerRows}</tbody>
                </table>
            </div>
        </div>
    `;
    highlightInlineSelection('team');
}

async function saveTeamLeaderAccount() {
    if (!appUser) return;
    if (adminRole !== 'TEAM') {
        showToast('Only team leaders can update this here.', 'error');
        return;
    }
    const usernameEl = document.getElementById('teamLeaderUsername');
    const currentEl = document.getElementById('teamLeaderCurrentPassword');
    const newEl = document.getElementById('teamLeaderNewPassword');
    const confirmEl = document.getElementById('teamLeaderConfirmPassword');
    const errorEl = document.getElementById('teamLeaderAccountError');
    if (!usernameEl || !currentEl || !newEl || !confirmEl) return;
    const nextUsername = formatJfaName(usernameEl.value || '');
    const current = (currentEl.value || '').trim();
    const next = (newEl.value || '').trim();
    const confirm = (confirmEl.value || '').trim();
    if (!nextUsername) {
        if (errorEl) {
            errorEl.textContent = 'Username cannot be blank.';
            errorEl.style.display = 'block';
        }
        return;
    }
    const validation = validateStrongPassword(next);
    if (!validation.ok) {
        if (errorEl) {
            errorEl.textContent = validation.message;
            errorEl.style.display = 'block';
        }
        return;
    }
    if (next !== confirm) {
        if (errorEl) {
            errorEl.textContent = 'New password confirmation does not match.';
            errorEl.style.display = 'block';
        }
        return;
    }
    const accounts = getUserAccounts();
    const key = normalizeJfaName(appUser);
    const account = accounts[key];
    if (!account) {
        if (errorEl) {
            errorEl.textContent = 'Account not found.';
            errorEl.style.display = 'block';
        }
        return;
    }
    const valid = await verifyAndMigrateAccountPassword(account, current, accounts, key);
    if (!valid) {
        if (errorEl) {
            errorEl.textContent = 'Current password is incorrect.';
            errorEl.style.display = 'block';
        }
        return;
    }
    const record = await createPasswordRecord(next);
    account.passwordHash = record.hash;
    account.passwordSalt = record.salt;
    delete account.password;
    const nextKey = normalizeJfaName(nextUsername);
    if (nextKey !== key && accounts[nextKey]) {
        if (errorEl) {
            errorEl.textContent = 'That username is already taken.';
            errorEl.style.display = 'block';
        }
        return;
    }
    account.username = nextUsername;
    account.updatedAt = new Date().toISOString();
    if (nextKey !== key) {
        delete accounts[key];
        accounts[nextKey] = account;
        appUser = nextUsername;
        sessionStorage.setItem(SESSION_KEYS.appUser, appUser);
        updateAppUserBadge();
        saveLastJfaIdentity(nextUsername, adminTeam);
    } else {
        accounts[key] = account;
    }
    saveUserAccounts(accounts);
    currentEl.value = '';
    newEl.value = '';
    confirmEl.value = '';
    if (errorEl) {
        errorEl.textContent = '';
        errorEl.style.display = 'none';
    }
    logUserMgmtAction('Password changed', `Account: ${nextUsername} (Team Leader)`);
    showToast('Account updated.', 'success');
}

function openTeamRiskJfa(name) {
    openAdminJfaDetail(name, 'team', true);
    const noteInput = document.getElementById('interventionNoteTeam');
    if (noteInput) noteInput.focus();
}

function openTeamLeaderSettings() {
    teamSettingsOpen = !teamSettingsOpen;
    renderTeamDetailPage(adminTeam);
    const card = document.getElementById('teamLeaderAccountCard');
    if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderTeamLeaderSettingsPanel(roster, teamName) {
    if (adminRole !== 'TEAM') return '';
    const rows = roster.map((entry) => {
        const key = normalizeJfaName(entry.name);
        const isArchived = archivedJfaNames.has(key);
        return `
            <tr>
                <td>${escapeHtml(entry.name)}</td>
                <td>${isArchived ? 'Inactive' : 'Active'}</td>
                <td>
                    <div class="menu-page-actions">
                        <button class="action-btn secondary" type="button" onclick="toggleTeamJfaStatus('${escapeHtml(entry.name)}', ${isArchived})">
                            ${isArchived ? 'Register' : 'Deregister'}
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
    return `
        <div class="insight-card" id="teamLeaderAccountCard">
            <h4>Team Leader Settings</h4>
            <p class="page-subtitle">Manage your account and register/deregister JFAs for ${escapeHtml(teamName)}.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="teamLeaderUsername">New Username</label>
                    <input type="text" id="teamLeaderUsername" value="${escapeHtml(formatJfaName(appUser || ''))}">
                </div>
                <div class="form-group">
                    <label for="teamLeaderCurrentPassword">Current Password</label>
                    <input type="password" id="teamLeaderCurrentPassword" autocomplete="current-password">
                </div>
                <div class="form-group">
                    <label for="teamLeaderNewPassword">New Password</label>
                    <input type="password" id="teamLeaderNewPassword" autocomplete="new-password">
                </div>
                <div class="form-group">
                    <label for="teamLeaderConfirmPassword">Confirm New Password</label>
                    <input type="password" id="teamLeaderConfirmPassword" autocomplete="new-password">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveTeamLeaderAccount()">Save Account Changes</button>
            </div>
            <div id="teamLeaderAccountError" class="modal-error" style="display:none;"></div>
            <div class="insight-card" style="margin-top:14px;">
                <h4>JFA Register / Deregister</h4>
                <div class="mini-table">
                    <table>
                        <thead>
                            <tr>
                                <th>JFA</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>${rows || '<tr><td colspan="3">No JFAs found.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

function toggleTeamJfaStatus(name, currentlyArchived) {
    if (adminRole !== 'TEAM') {
        showToast('Only team leaders can manage this.', 'error');
        return;
    }
    const normalized = normalizeJfaName(name);
    if (!normalized) return;
    if (currentlyArchived) {
        archivedJfaNames.delete(normalized);
    } else {
        archivedJfaNames.add(normalized);
    }
    scheduleStorageWrite(STORAGE_KEYS.archivedJfas, JSON.stringify([...archivedJfaNames]));
    renderTeamDetailPage(adminTeam);
    showToast(currentlyArchived ? 'JFA registered.' : 'JFA deregistered.', 'success');
}

function openTeamArchives() {
    if (adminRole === 'PERSONAL') {
        showToast('Select a team or admin role first.', 'error');
        return;
    }
    closeMenuPage();
    goToPage('archives-page');
}

function openLeadsTab(tab = 'submit') {
    const submitPanel = document.getElementById('leadSubmitPanel');
    const viewPanel = document.getElementById('leadViewPanel');
    const submitBtn = document.getElementById('leadSubmitTabBtn');
    const viewBtn = document.getElementById('leadViewTabBtn');
    if (!submitPanel || !viewPanel || !submitBtn || !viewBtn) return;
    const isSubmit = tab === 'submit';
    submitPanel.style.display = isSubmit ? 'block' : 'none';
    viewPanel.style.display = isSubmit ? 'none' : 'block';
    submitBtn.classList.toggle('secondary', !isSubmit);
    viewBtn.classList.toggle('secondary', isSubmit);
    submitBtn.classList.toggle('is-active', isSubmit);
    viewBtn.classList.toggle('is-active', !isSubmit);
    submitBtn.setAttribute('aria-pressed', isSubmit ? 'true' : 'false');
    viewBtn.setAttribute('aria-pressed', isSubmit ? 'false' : 'true');
    renderLeadBrokerAuthorityCode();
    if (isSubmit) {
        preflightLeadGeotagCapture().catch(() => {});
    }
    if (!isSubmit) {
        renderMyLeads();
    }
}

function renderLeadBrokerAuthorityCode() {
    const codeEl = document.getElementById('leadBrokerAuthorityCode');
    if (!codeEl) return;
    const configured = String(window.JFA_BROKER_AUTHORITY_CODE || '').trim();
    const fallback = DEFAULT_BROKER_AUTHORITY_CODE;
    const code = configured || fallback;
    codeEl.textContent = `Broker Authority Code: ${code}`;
}

function getLeadSignatureCanvasContext() {
    const canvas = document.getElementById('leadSignaturePad');
    if (!(canvas instanceof HTMLCanvasElement)) return null;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    return { canvas, ctx };
}

function drawLeadSignatureLine(ctx, fromX, fromY, toX, toY) {
    ctx.beginPath();
    ctx.moveTo(fromX, fromY);
    ctx.lineTo(toX, toY);
    ctx.strokeStyle = '#0B2E52';
    ctx.lineWidth = 2.2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.stroke();
}

function drawLeadSignatureStrokes(ctx) {
    if (!Array.isArray(leadSignatureState.strokes) || !leadSignatureState.strokes.length) return;
    leadSignatureState.strokes.forEach((stroke) => {
        if (!Array.isArray(stroke) || stroke.length < 2) return;
        for (let i = 1; i < stroke.length; i++) {
            const from = stroke[i - 1];
            const to = stroke[i];
            drawLeadSignatureLine(ctx, from.x, from.y, to.x, to.y);
        }
    });
}

function renderLeadSignaturePadSurface(ctx, width, height) {
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = 'rgba(10, 19, 36, 0.18)';
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, 0.5, width - 1, height - 1);
}

function redrawLeadSignaturePadFromState() {
    const found = getLeadSignatureCanvasContext();
    if (!found) return;
    const { canvas, ctx } = found;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(320, Math.round(rect.width || canvas.clientWidth || 900));
    const height = Math.max(140, Math.round(rect.height || canvas.clientHeight || 240));
    renderLeadSignaturePadSurface(ctx, width, height);
    const finish = () => {
        drawLeadSignatureStrokes(ctx);
        leadSignatureState.hasSignature = Boolean(leadSignatureState.baseImageData || (leadSignatureState.strokes && leadSignatureState.strokes.length));
        updateLeadSignatureDataFromCanvas();
    };
    if (leadSignatureState.baseImageData) {
        const image = new Image();
        image.onload = () => {
            ctx.drawImage(image, 0, 0, width, height);
            finish();
        };
        image.src = leadSignatureState.baseImageData;
        return;
    }
    finish();
}

function updateLeadSignatureDataFromCanvas() {
    const found = getLeadSignatureCanvasContext();
    if (!found) return '';
    const { canvas } = found;
    if (!leadSignatureState.hasSignature) {
        leadSignatureState.hasSignature = Boolean(leadSignatureState.baseImageData || (leadSignatureState.strokes && leadSignatureState.strokes.length));
    }
    const data = leadSignatureState.hasSignature ? canvas.toDataURL('image/png') : '';
    const hidden = document.getElementById('leadSignatureData');
    if (hidden) hidden.value = data;
    const hint = document.getElementById('leadSignatureHint');
    if (hint) {
        hint.textContent = leadSignatureState.hasSignature
            ? 'Signature captured.'
            : 'Use finger, mouse, or trackpad to sign.';
    }
    return data;
}

function resizeLeadSignatureCanvas() {
    const found = getLeadSignatureCanvasContext();
    if (!found) return;
    const { canvas, ctx } = found;
    const ratio = Math.max(window.devicePixelRatio || 1, 1);
    const rect = canvas.getBoundingClientRect();
    const displayWidth = Math.max(320, Math.round(rect.width || canvas.clientWidth || 900));
    const displayHeight = Math.max(140, Math.round(rect.height || canvas.clientHeight || 240));
    canvas.width = Math.round(displayWidth * ratio);
    canvas.height = Math.round(displayHeight * ratio);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(ratio, ratio);
    redrawLeadSignaturePadFromState();
}

function getLeadSignaturePoint(event, canvas) {
    const rect = canvas.getBoundingClientRect();
    return {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top
    };
}

function clearLeadSignaturePad(triggerSave = true) {
    const found = getLeadSignatureCanvasContext();
    if (!found) return;
    leadSignatureState.baseImageData = '';
    leadSignatureState.strokes = [];
    leadSignatureState.currentStroke = [];
    leadSignatureState.hasSignature = false;
    leadSignatureState.isDrawing = false;
    resizeLeadSignatureCanvas();
    if (triggerSave) saveLeadDraft();
}

function undoLeadSignatureStroke() {
    if (leadSignatureState.isDrawing) return;
    if (leadSignatureState.strokes && leadSignatureState.strokes.length) {
        leadSignatureState.strokes.pop();
    } else if (leadSignatureState.baseImageData) {
        leadSignatureState.baseImageData = '';
    } else {
        showToast('No signature stroke to undo.', 'error');
        return;
    }
    leadSignatureState.hasSignature = Boolean(leadSignatureState.baseImageData || (leadSignatureState.strokes && leadSignatureState.strokes.length));
    redrawLeadSignaturePadFromState();
    saveLeadDraft();
}

function setLeadSignatureImage(dataUrl, triggerSave = false) {
    const found = getLeadSignatureCanvasContext();
    if (!found) return;
    resizeLeadSignatureCanvas();
    if (!dataUrl) {
        leadSignatureState.baseImageData = '';
        leadSignatureState.strokes = [];
        leadSignatureState.currentStroke = [];
        leadSignatureState.hasSignature = false;
        redrawLeadSignaturePadFromState();
        if (triggerSave) saveLeadDraft();
        return;
    }
    leadSignatureState.baseImageData = dataUrl;
    leadSignatureState.strokes = [];
    leadSignatureState.currentStroke = [];
    leadSignatureState.hasSignature = true;
    redrawLeadSignaturePadFromState();
    if (triggerSave) saveLeadDraft();
}

function setupLeadSignaturePad() {
    const found = getLeadSignatureCanvasContext();
    if (!found) return;
    const { canvas, ctx } = found;
    if (!leadSignatureState.ready) {
        canvas.style.touchAction = 'none';
        canvas.addEventListener('pointerdown', (event) => {
            const point = getLeadSignaturePoint(event, canvas);
            leadSignatureState.isDrawing = true;
            leadSignatureState.lastX = point.x;
            leadSignatureState.lastY = point.y;
            leadSignatureState.currentStroke = [point];
            canvas.setPointerCapture(event.pointerId);
        });
        canvas.addEventListener('pointermove', (event) => {
            if (!leadSignatureState.isDrawing) return;
            const point = getLeadSignaturePoint(event, canvas);
            drawLeadSignatureLine(ctx, leadSignatureState.lastX, leadSignatureState.lastY, point.x, point.y);
            leadSignatureState.currentStroke.push(point);
            leadSignatureState.lastX = point.x;
            leadSignatureState.lastY = point.y;
            leadSignatureState.hasSignature = true;
        });
        const finishStroke = (event) => {
            if (!leadSignatureState.isDrawing) return;
            leadSignatureState.isDrawing = false;
            if (Array.isArray(leadSignatureState.currentStroke) && leadSignatureState.currentStroke.length > 1) {
                leadSignatureState.strokes.push(leadSignatureState.currentStroke);
            }
            leadSignatureState.currentStroke = [];
            try {
                canvas.releasePointerCapture(event.pointerId);
            } catch (_) {
                // ignore
            }
            updateLeadSignatureDataFromCanvas();
            saveLeadDraft();
        };
        canvas.addEventListener('pointerup', finishStroke);
        canvas.addEventListener('pointerleave', finishStroke);
        canvas.addEventListener('pointercancel', finishStroke);
        leadSignatureState.ready = true;
    }
    if (!leadSignatureState.resizeBound) {
        window.addEventListener('resize', debounce(() => {
            const leadPageOpen = document.getElementById('leadsPage')?.classList.contains('is-open');
            if (leadPageOpen) resizeLeadSignatureCanvas();
        }, 120));
        leadSignatureState.resizeBound = true;
    }
    resizeLeadSignatureCanvas();
}

function setupLeadForm() {
    const form = document.getElementById('leadForm');
    if (!form) return;
    renderLeadBrokerAuthorityCode();
    setupLeadSignaturePad();
    hydrateLeadDraft();
    const draftHandler = debounce(() => saveLeadDraft(), 600);
    form.addEventListener('input', draftHandler);
    form.addEventListener('change', draftHandler);
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const identity = getLeadIdentity();
        if (!identity?.name) {
            showToast('Please register first so your leads can be linked to your profile.', 'error');
            navigateToRegister();
            return;
        }

        const clientName = document.getElementById('leadClientName')?.value?.trim();
        const clientId = document.getElementById('leadClientId')?.value?.trim();
        const clientPersal = document.getElementById('leadClientPersal')?.value?.trim() || '';
        const clientAddress = document.getElementById('leadClientAddress')?.value?.trim();
        const clientCell = document.getElementById('leadClientCell')?.value?.trim();
        const clientHome = document.getElementById('leadClientHome')?.value?.trim() || '';
        const clientEmail = document.getElementById('leadClientEmail')?.value?.trim() || '';
        const authorizedUser = document.getElementById('leadAuthorizedUser')?.value?.trim() || '';
        const authorizedId = document.getElementById('leadAuthorizedId')?.value?.trim() || '';
        const authorizedEmail = document.getElementById('leadAuthorizedEmail')?.value?.trim() || '';
        const intermediary = document.getElementById('leadIntermediary')?.value?.trim() || 'Matla Life Investment';
        const wantsWill = document.getElementById('leadWill')?.checked || false;
        const signedAt = document.getElementById('leadSignedAt')?.value?.trim() || '';
        const signedDate = document.getElementById('leadSignedDate')?.value || '';
        const clientSignature = document.getElementById('leadClientSignature')?.value?.trim();
        const signatureData = document.getElementById('leadSignatureData')?.value?.trim() || '';
        const notes = document.getElementById('leadNotes')?.value?.trim() || '';
        const appointmentDate = document.getElementById('leadAppointmentDate')?.value?.trim() || '';
        const appointmentTime = document.getElementById('leadAppointmentTime')?.value?.trim() || '';
        const consent = document.getElementById('leadClientConsent')?.checked;
        const productChecks = Array.from(document.querySelectorAll('input[name="leadProducts"]:checked'));
        const products = productChecks.map((input) => input.value);
        const otherProduct = document.getElementById('leadOtherProduct')?.value?.trim() || '';
        if (otherProduct) products.push(`Other: ${otherProduct}`);
        const productSummary = products.length === 0 ? 'Unspecified' : products.length === 1 ? products[0] : 'Multiple';

        if (!clientName || !clientId || !clientAddress || !clientCell || !clientSignature || !consent || !signatureData) {
            showToast('Please complete all required lead fields, capture a signature, and confirm client consent.', 'error');
            return;
        }
        if (clientEmail && !isValidEmail(clientEmail)) {
            showToast('Please enter a valid email address.', 'error');
            return;
        }
        if (!isValidPhone(clientCell)) {
            showToast('Please enter a valid cell number.', 'error');
            return;
        }
        if (clientHome && !isValidPhone(clientHome)) {
            showToast('Please enter a valid home number.', 'error');
            return;
        }
        if ((appointmentDate && !appointmentTime) || (!appointmentDate && appointmentTime)) {
            showToast('Complete both appointment date and time, or leave both empty.', 'error');
            return;
        }
        const duplicateLead = findDuplicateLeadSubmission(identity, clientName, clientId, clientCell);
        if (duplicateLead) {
            const timeLabel = duplicateLead.timestamp
                ? new Date(duplicateLead.timestamp).toLocaleString('en-ZA')
                : 'recently';
            const lid = duplicateLead.leadId || 'Unknown LID';
            showToast(`Possible duplicate lead detected (${lid}, ${timeLabel}). Edit existing lead instead.`, 'error');
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Submitting...';
        }

        const geo = await getLeadGeolocation();
        const hasGeoCoords = Boolean(
            geo?.coords &&
            Number.isFinite(geo.coords.lat) &&
            Number.isFinite(geo.coords.lng)
        );
        if (!hasGeoCoords) {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit Lead';
            }
            const geoStatus = getGeoStatusLabel(geo?.status || 'unavailable');
            showToast(`Geotag is required before lead submission (${geoStatus}). Enable location and try again.`, 'error');
            return;
        }
        const safeGeo = geo?.coords
            ? {
                status: geo.status || 'ok',
                coords: {
                    lat: Number.isFinite(geo.coords.lat) ? Number(geo.coords.lat.toFixed(6)) : null,
                    lng: Number.isFinite(geo.coords.lng) ? Number(geo.coords.lng.toFixed(6)) : null,
                    accuracy: Number.isFinite(geo.coords.accuracy) ? Math.round(geo.coords.accuracy) : null
                }
            }
            : { status: geo?.status || 'unavailable' };
        let uniqueLeadId = '';
        try {
            uniqueLeadId = await allocateUniqueLeadId();
        } catch (_) {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit Lead';
            }
            showToast('Unable to allocate a unique LID right now. Please try again.', 'error');
            return;
        }
        const entry = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            timestamp: new Date().toISOString(),
            status: normalizeLeadStatus('New'),
            paymentStatus: normalizePaymentStatus('Pending'),
            failureReason: '',
            commissionDate: '',
            leadId: uniqueLeadId,
            jfaName: identity.name,
            jfaTeam: identity.team || '',
            clientNameRaw: clientName,
            clientName: maskSensitive(clientName, 1, 0),
            clientIdRaw: clientId,
            clientId: maskSensitive(clientId, 2, 2),
            clientPersalRaw: clientPersal,
            clientPersal: maskSensitive(clientPersal, 2, 2),
            clientAddressRaw: clientAddress,
            clientAddress: summarizeAddress(clientAddress),
            clientCellRaw: clientCell,
            clientCell: maskSensitive(clientCell, 3, 2),
            clientHomeRaw: clientHome,
            clientHome: maskSensitive(clientHome, 3, 2),
            clientEmailRaw: clientEmail,
            clientEmail: maskSensitive(clientEmail, 2, 4),
            authorizedUser,
            authorizedIdRaw: authorizedId,
            authorizedId: maskSensitive(authorizedId, 2, 2),
            authorizedEmailRaw: authorizedEmail,
            authorizedEmail: maskSensitive(authorizedEmail, 2, 4),
            intermediary,
            wantsWill,
            signedAt,
            signedDate,
            clientSignature: clientSignature ? 'Captured' : '',
            clientSignatureImage: signatureData,
            product: productSummary,
            productList: products,
            notes,
            appointmentDate,
            appointmentTime,
            geo: safeGeo,
            geoCapturedAt: new Date().toISOString()
        };
        leadRecords.push(entry);
        try {
            localStorage.setItem(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
            updateLastSaved();
            scheduleRemoteSync();
        } catch (_) {
            // fallback to scheduled write below
        }
        scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
        await syncCriticalCloudState('Lead');
        if (appointmentDate && appointmentTime) {
            const appointmentResult = scheduleAppointmentFromLead(entry, appointmentDate, appointmentTime);
            if (!appointmentResult?.ok) {
                showToast(`Lead submitted, but appointment not saved: ${appointmentResult?.message || 'unknown error'}`, 'error');
            }
            dispatchOneHourAppointmentReminders();
        }
        clearLeadDraft();
        applyLeadSubmissionToDailyStats(identity.name);
        const geoSummary = getLeadGeoSummary(entry);
        logAudit('Lead submitted', `${identity.name} • ${identity.team || 'No Team'} • ${productSummary} • Geo: ${geoSummary.statusLabel}`);
        form.reset();
        clearLeadSignaturePad(false);
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit Lead';
        }
        const lidNotice = `Lead submitted. Client LID: ${uniqueLeadId}. Geo: ${geoSummary.statusLabel}.`;
        const notifyUserKey = normalizeJfaName(appUser || identity.name || '');
        if (notifyUserKey) {
            pushSystemNotification('USER', '', 'Lead Submitted', lidNotice, {
                userKey: notifyUserKey,
                type: 'LEAD_SUBMITTED',
                preview: `Client LID: ${uniqueLeadId}`,
                createdBy: formatJfaName(identity.name || appUser || 'System'),
                createdRole: adminRole || 'USER'
            });
        }
        showToast(lidNotice, 'success');
        renderMyLeads();
        if (activeMenuPage === 'appointments') {
            renderAppointmentsPage();
        } else if (activeMenuPage === 'benSystem') {
            renderBenSystemPage();
        }
    });
}

function renderMyLeads() {
    const summaryEl = document.getElementById('leadViewSummary');
    const breakdownEl = document.getElementById('leadViewBreakdown');
    if (!summaryEl || !breakdownEl) return;
    const identity = getLeadIdentity();
    if (!identity?.name) {
        summaryEl.innerHTML = '<div class="summary-item"><span class="summary-label">No signed-in JFA profile found.</span></div>';
        breakdownEl.innerHTML = '<p class="menu-page-note">Register first to view your lead totals.</p>';
        return;
    }
    const normName = normalizeJfaName(identity.name);
    const mine = leadRecords.filter((l) => normalizeJfaName(l.jfaName) === normName);
    const now = new Date();
    const today = todayKey();
    const weekStart = getStartOfWeek(now);
    const monthStart = getStartOfMonth(now);
    const todayCount = mine.filter((l) => dateKeyLocal(new Date(l.timestamp)) === today).length;
    const weekCount = mine.filter((l) => {
        const d = new Date(l.timestamp);
        return d >= weekStart && d <= now;
    }).length;
    const monthCount = mine.filter((l) => {
        const d = new Date(l.timestamp);
        return d >= monthStart && d <= now;
    }).length;
    const geoCapturedCount = mine.filter((lead) => {
        const status = String(lead?.geo?.status || '').toLowerCase();
        return status === 'ok' || status === 'cached';
    }).length;
    const geoIssueCount = Math.max(0, mine.length - geoCapturedCount);

    summaryEl.innerHTML = `
        <div class="summary-item"><span class="summary-value">${mine.length}</span><span class="summary-label">Total Leads</span></div>
        <div class="summary-item"><span class="summary-value">${todayCount}</span><span class="summary-label">Today</span></div>
        <div class="summary-item"><span class="summary-value">${weekCount}</span><span class="summary-label">This Week</span></div>
        <div class="summary-item"><span class="summary-value">${monthCount}</span><span class="summary-label">This Month</span></div>
        <div class="summary-item"><span class="summary-value">${geoCapturedCount}</span><span class="summary-label">Geo Captured</span></div>
        <div class="summary-item"><span class="summary-value">${geoIssueCount}</span><span class="summary-label">Geo Pending/Issue</span></div>
    `;

    if (!mine.length) {
        breakdownEl.innerHTML = '<p class="menu-page-note">No leads submitted yet.</p>';
        return;
    }

    const perDay = new Map();
    mine.forEach((lead) => {
        const key = dateKeyLocal(new Date(lead.timestamp));
        perDay.set(key, (perDay.get(key) || 0) + 1);
    });
    const rows = [...perDay.entries()]
        .sort((a, b) => b[0].localeCompare(a[0]))
        .slice(0, 14)
        .map(([date, count]) => `<tr><td>${date}</td><td>${count}</td></tr>`)
        .join('');
    const leadRows = [...mine]
        .sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
        .slice(0, 30)
        .map((lead) => {
            const rawName = String(lead.clientNameRaw || '').trim();
            const maskedName = String(lead.clientName || '').trim();
            const client = hasMasterAdminAccess() ? (rawName || maskedName || 'Client') : (maskedName || 'Client');
            const lid = String(lead.leadId || '—').trim();
            const when = lead.timestamp ? new Date(lead.timestamp).toLocaleString('en-ZA') : '—';
            return `
                <tr>
                    <td>${escapeHtml(client || 'Client')}</td>
                    <td>${escapeHtml(lid)}</td>
                    <td>${escapeHtml(when)}</td>
                </tr>
            `;
        })
        .join('');

    breakdownEl.innerHTML = `
        <h4 style="margin:0 0 8px;">Daily Lead Totals</h4>
        <table>
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Leads Captured</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
        <h4 style="margin:14px 0 8px;">My Clients (Name & LID)</h4>
        <div class="learning-search" style="margin-bottom:8px;">
            <input type="text" id="myLeadSearchInput" placeholder="Search by client name or LID..." oninput="filterMyLeadsTable(this.value)">
        </div>
        <table>
            <thead>
                <tr>
                    <th>Client Name & Surname</th>
                    <th>LID</th>
                    <th>Submitted At</th>
                </tr>
            </thead>
            <tbody id="myLeadsTbody">${leadRows || '<tr><td colspan="3">No leads submitted yet.</td></tr>'}</tbody>
        </table>
    `;
}

function filterMyLeadsTable(query = '') {
    const tbody = document.getElementById('myLeadsTbody');
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr'));
    if (!rows.length) return;
    const term = String(query || '').trim().toLowerCase();
    rows.forEach((row) => {
        const hay = String(row.textContent || '').toLowerCase();
        row.style.display = !term || hay.includes(term) ? '' : 'none';
    });
}

function isValidEmail(value) {
    const raw = String(value || '').trim();
    if (!raw) return true;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw);
}

function isValidPhone(value) {
    const raw = String(value || '').trim();
    if (!raw) return false;
    const digits = raw.replace(/\D/g, '');
    return digits.length >= 7;
}

function renderLeadDraftNotice(updatedAt = '') {
    const notice = document.getElementById('leadDraftNotice');
    if (!notice) return;
    const raw = String(updatedAt || '').trim();
    if (!raw) {
        notice.style.display = 'none';
        notice.innerHTML = '';
        return;
    }
    const when = new Date(raw);
    const stamp = Number.isFinite(when.getTime()) ? when.toLocaleString('en-ZA') : raw;
    notice.style.display = '';
    notice.innerHTML = `
        <div class="lead-draft-notice-text">
            Draft recovered from <strong>${escapeHtml(stamp)}</strong>. You can continue editing or discard it.
        </div>
        <div class="lead-draft-notice-actions">
            <button class="action-btn secondary" type="button" onclick="dismissLeadDraftNotice()">Dismiss</button>
            <button class="action-btn secondary" type="button" onclick="clearLeadDraft(true)">Discard Draft</button>
        </div>
    `;
}

function dismissLeadDraftNotice() {
    renderLeadDraftNotice('');
}

function getLeadDraftPayload() {
    return {
        clientName: document.getElementById('leadClientName')?.value || '',
        clientId: document.getElementById('leadClientId')?.value || '',
        clientPersal: document.getElementById('leadClientPersal')?.value || '',
        clientAddress: document.getElementById('leadClientAddress')?.value || '',
        clientCell: document.getElementById('leadClientCell')?.value || '',
        clientHome: document.getElementById('leadClientHome')?.value || '',
        clientEmail: document.getElementById('leadClientEmail')?.value || '',
        authorizedUser: document.getElementById('leadAuthorizedUser')?.value || '',
        authorizedId: document.getElementById('leadAuthorizedId')?.value || '',
        authorizedEmail: document.getElementById('leadAuthorizedEmail')?.value || '',
        wantsWill: document.getElementById('leadWill')?.checked || false,
        signedAt: document.getElementById('leadSignedAt')?.value || '',
        signedDate: document.getElementById('leadSignedDate')?.value || '',
        clientSignature: document.getElementById('leadClientSignature')?.value || '',
        signatureData: document.getElementById('leadSignatureData')?.value || '',
        notes: document.getElementById('leadNotes')?.value || '',
        appointmentDate: document.getElementById('leadAppointmentDate')?.value || '',
        appointmentTime: document.getElementById('leadAppointmentTime')?.value || '',
        otherProduct: document.getElementById('leadOtherProduct')?.value || '',
        products: Array.from(document.querySelectorAll('input[name=\"leadProducts\"]:checked')).map((input) => input.value),
        consent: document.getElementById('leadClientConsent')?.checked || false
    };
}

function saveLeadDraft() {
    const payload = getLeadDraftPayload();
    const hasContent = Object.values(payload).some((value) => {
        if (Array.isArray(value)) return value.length > 0;
        return Boolean(String(value).trim());
    });
    if (!hasContent) return;
    scheduleStorageWrite(STORAGE_KEYS.leadDraft, JSON.stringify({
        updatedAt: new Date().toISOString(),
        data: payload
    }));
}

function hydrateLeadDraft() {
    const raw = localStorage.getItem(STORAGE_KEYS.leadDraft);
    if (!raw) return;
    let draft = null;
    try {
        draft = JSON.parse(raw);
    } catch (_) {
        return;
    }
    const data = draft?.data;
    if (!data) return;
    leadDraftRecoveredAt = String(draft?.updatedAt || '');
    const setValue = (id, value) => {
        const el = document.getElementById(id);
        if (!el || value == null) return;
        el.value = value;
    };
    setValue('leadClientName', data.clientName);
    setValue('leadClientId', data.clientId);
    setValue('leadClientPersal', data.clientPersal);
    setValue('leadClientAddress', data.clientAddress);
    setValue('leadClientCell', data.clientCell);
    setValue('leadClientHome', data.clientHome);
    setValue('leadClientEmail', data.clientEmail);
    setValue('leadAuthorizedUser', data.authorizedUser);
    setValue('leadAuthorizedId', data.authorizedId);
    setValue('leadAuthorizedEmail', data.authorizedEmail);
    setValue('leadSignedAt', data.signedAt);
    setValue('leadSignedDate', data.signedDate);
    setValue('leadClientSignature', data.clientSignature);
    setValue('leadNotes', data.notes);
    setValue('leadAppointmentDate', data.appointmentDate);
    setValue('leadAppointmentTime', data.appointmentTime);
    setValue('leadOtherProduct', data.otherProduct);
    const willEl = document.getElementById('leadWill');
    if (willEl) willEl.checked = Boolean(data.wantsWill);
    const consentEl = document.getElementById('leadClientConsent');
    if (consentEl) consentEl.checked = Boolean(data.consent);
    if (Array.isArray(data.products)) {
        const checks = document.querySelectorAll('input[name=\"leadProducts\"]');
        checks.forEach((input) => {
            input.checked = data.products.includes(input.value);
        });
    }
    setLeadSignatureImage(data.signatureData || '', false);
    renderLeadDraftNotice(leadDraftRecoveredAt);
}

function clearLeadDraft(resetForm = false) {
    localStorage.removeItem(STORAGE_KEYS.leadDraft);
    leadDraftRecoveredAt = '';
    renderLeadDraftNotice('');
    if (resetForm) {
        const form = document.getElementById('leadForm');
        if (form) form.reset();
        clearLeadSignaturePad(false);
    }
}

function adjustMyConsentFormsToday() {
    const identity = getLeadIdentity();
    if (!identity?.name) {
        showToast('Register first to adjust today consent forms.', 'error');
        return;
    }
    const idx = getLatestTodayRecordIndexByName(identity.name);
    if (idx < 0) {
        showToast('No DBD record found for today.', 'error');
        return;
    }
    const record = jfaRecords[idx];
    const currentTotal = Number.isFinite(record.consentForms) ? record.consentForms : 0;
    const input = prompt(`Enter corrected consent forms for today (${formatJfaName(identity.name)}).`, String(currentTotal));
    if (input === null) return;
    const next = parseInt(String(input).trim(), 10);
    if (Number.isNaN(next) || next < 0) {
        showToast('Please enter a valid non-negative number.', 'error');
        return;
    }
    const previous = currentTotal;
    const leadAutoCount = getTodayLeadCountForName(identity.name);
    record.consentForms = next;
    record.leadAutoCount = leadAutoCount;
    record.physicalConsentForms = Math.max(0, next - leadAutoCount);
    record.manualConsentAdjustment = record.physicalConsentForms;
    const delta = next - previous;
    if (delta !== 0 && record.facility?.id) {
        const facility = getFacilityById(record.facility.id);
        if (facility) {
            facility.consentForms = Math.max(0, (facility.consentForms || 0) + delta);
        }
        saveFacilityStats();
    }
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    const lastDbd = JSON.parse(localStorage.getItem(STORAGE_KEYS.lastDbd) || 'null');
    if (lastDbd && normalizeJfaName(lastDbd.name) === normalizeJfaName(identity.name) && recordDateKey(lastDbd) === todayKey()) {
        scheduleStorageWrite(STORAGE_KEYS.lastDbd, JSON.stringify({
            ...lastDbd,
            consentForms: next,
            leadAutoCount,
            manualConsentAdjustment: record.manualConsentAdjustment,
            physicalConsentForms: record.physicalConsentForms
        }));
    }
    showToast('Today consent forms updated.', 'success');
    syncConsentInputWithAutoCount();
    updateSummary();
    updateStatistics();
    updateHeroSummary();
    renderMyLeads();
}

function renderLeadGeotagsForAdmin(name) {
    if (adminRole !== 'ADMIN') return '';
    const normalized = normalizeJfaName(name);
    const mine = leadRecords
        .filter((l) => normalizeJfaName(l.jfaName) === normalized)
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

    if (!mine.length) {
        return '<p class="page-subtitle">No leads captured for this JFA yet.</p>';
    }

    const rows = mine.slice(0, 10).map((lead) => {
        const when = lead.timestamp ? new Date(lead.timestamp).toLocaleString('en-ZA') : '—';
        const geo = getLeadGeoSummary(lead);
        return `
            <tr>
                <td>${escapeHtml(when)}</td>
                <td>${escapeHtml(lead.product || '—')}</td>
                <td>${escapeHtml(geo.coordsText)}</td>
                <td>${escapeHtml(geo.accuracyText)}</td>
                <td>${escapeHtml(geo.statusLabel)}</td>
            </tr>
        `;
    }).join('');

    return `
        <div class="mini-table">
            <table>
                <thead>
                    <tr>
                        <th>Captured</th>
                        <th>Product</th>
                        <th>Coordinates</th>
                        <th>Accuracy</th>
                        <th>Geo Status</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function exportMyLeadsSummaryCsv() {
    const identity = getLeadIdentity();
    if (!identity?.name) {
        showToast('Register first to export your lead summary.', 'error');
        return;
    }
    const normName = normalizeJfaName(identity.name);
    const mine = leadRecords.filter((l) => normalizeJfaName(l.jfaName) === normName);
    if (!mine.length) {
        showToast('No leads found to export.', 'error');
        return;
    }

    const now = new Date();
    const today = todayKey();
    const weekStart = getStartOfWeek(now);
    const monthStart = getStartOfMonth(now);
    const todayCount = mine.filter((l) => dateKeyLocal(new Date(l.timestamp)) === today).length;
    const weekCount = mine.filter((l) => {
        const d = new Date(l.timestamp);
        return d >= weekStart && d <= now;
    }).length;
    const monthCount = mine.filter((l) => {
        const d = new Date(l.timestamp);
        return d >= monthStart && d <= now;
    }).length;

    const perDay = new Map();
    mine.forEach((lead) => {
        const key = dateKeyLocal(new Date(lead.timestamp));
        perDay.set(key, (perDay.get(key) || 0) + 1);
    });
    const dailyRows = [...perDay.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([date, count]) => [date, count]);

    const headers = ['Section', 'Date', 'Value'];
    const rows = [
        ['Summary', 'Total Leads', mine.length],
        ['Summary', 'Today', todayCount],
        ['Summary', 'This Week', weekCount],
        ['Summary', 'This Month', monthCount],
        ...dailyRows.map(([date, count]) => ['Daily Breakdown', date, count])
    ];
    const safeName = formatJfaName(identity.name).replace(/\s+/g, '-').toLowerCase();
    exportCsvWithHeaders(headers, rows, `my-lead-summary-${safeName}.csv`);
}

function showLearning(key) {
    const learningBody = document.getElementById('learningBody');
    const productBody = document.getElementById('productBody');
    if (!learningBody || !productBody) return;
    localStorage.setItem('lastLearningKey', key);
    const text = getLearningContent(key) || 'Content coming soon.';
    const pages = buildLearningPages(text);
    if (!learningPageState[key]) learningPageState[key] = 0;
    renderLearningPage(key, pages);
    openLearningDetail(key);
    updateLearningResumeButton();
    updateLearningBookmarkButton();
}

function renderAdminInsights() {
    const container = document.getElementById('adminInsights');
    if (!container) return;
    if (adminRole === 'PERSONAL') {
        container.innerHTML = '<p class="menu-page-note">Admin insights are available to team leaders and admins.</p>';
        return;
    }
    const scoped = getScopedRecords();
    const today = todayKey();
    const presentToday = scoped
        .filter((r) => recordDateKey(r) === today)
        .filter((r) => !isTeamLeaderName(r.name, r.team || ''))
        .map((r) => formatJfaName(r.name))
        .filter(Boolean);
    const uniquePresent = [...new Set(presentToday)].sort();

    const now = new Date();
    const monthStart = getStartOfMonth(now);
    const workingDays = getWorkingDays(monthStart, now);
    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, now),
        ...jfaRecords.filter((r) => r.timestamp)
    ].filter(recordMatchesScope);

    const stats = new Map();
    monthRecords.forEach((record) => {
        if (!record.name) return;
        if (isTeamLeaderName(record.name, record.team || '')) return;
        const key = normalizeJfaName(record.name);
        const entry = stats.get(key) || {
            name: formatJfaName(record.name),
            present: new Set(),
            forms: 0,
            late: 0,
            caution: 0
        };
        entry.forms += record.consentForms || 0;
        const dateKey = recordDateKey(record);
        if (dateKey) entry.present.add(dateKey);
        if (record.checkInStatus === 'LATE') entry.late += 1;
        if (record.checkInStatus === 'CAUTION') entry.caution += 1;
        stats.set(key, entry);
    });

    const all = [...stats.values()];
    const absentOften = all
        .map((entry) => ({ ...entry, absences: Math.max(0, workingDays.length - entry.present.size) }))
        .filter((entry) => entry.absences >= 3)
        .sort((a, b) => b.absences - a.absences)
        .slice(0, 8);
    const underPerformers = all
        .filter((entry) => entry.forms < 10)
        .sort((a, b) => a.forms - b.forms)
        .slice(0, 8);

    const renderChips = (items, emptyLabel, danger = false) => {
        if (!items.length) return `<span class="insight-chip">${emptyLabel}</span>`;
        return items
            .map((item) => {
                const name = typeof item === 'string' ? item : (item.name || '');
                const label = item?.absences != null
                    ? `${name} (${item.absences} absences)`
                    : item?.forms != null
                        ? `${name} (${item.forms} forms)`
                        : name;
                if (!name) return `<span class="insight-chip ${danger ? 'danger' : ''}">${label}</span>`;
                return `<button class="insight-chip ${danger ? 'danger' : ''}" type="button" onclick="openAdminJfaDetail('${escapeHtml(name)}','admin')">${label}</button>`;
            })
            .join('');
    };

    container.innerHTML = `
        <div class="insight-card">
            <h4>Present Today</h4>
            <div class="insight-list">${renderChips(uniquePresent, 'No check-ins yet')}</div>
        </div>
        <div class="insight-card">
            <h4>Absent Often</h4>
            <div class="insight-list">${renderChips(absentOften, 'No frequent absences', true)}</div>
        </div>
        <div class="insight-card">
            <h4>Underperformers (Monthly)</h4>
            <div class="insight-list">${renderChips(underPerformers, 'No underperformers', true)}</div>
        </div>
    `;
}

function renderAdminTeamDetails() {
    const detail = document.getElementById('adminTeamDetail');
    const list = document.getElementById('adminJfaList');
    const inline = document.getElementById('adminJfaInlineDetail');
    if (!detail || !list) return;
    if (adminRole === 'PERSONAL') {
        detail.innerHTML = '<p class="menu-page-note">Select a team or admin view to see team detail.</p>';
        list.innerHTML = '';
        if (inline) inline.innerHTML = '';
        activeInlineDetail.admin = null;
        return;
    }
    if (inline) inline.innerHTML = '';
    activeInlineDetail.admin = null;
    const scoped = getScopedRecords();
    const today = todayKey();
    const todayRecords = scoped.filter((r) => recordDateKey(r) === today);
    const summaryTotal = scoped.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const avgPerJfa = scoped.length ? (summaryTotal / scoped.length).toFixed(1) : '0';
    const scopedJfaOnly = scoped.filter((r) => !isTeamLeaderName(r.name, r.team || ''));
    const topJfa = topBy(scopedJfaOnly, (r) => r.name);

    detail.innerHTML = `
        <div class="insight-card">
            <h4>Team Summary</h4>
            <div class="insight-list">
                <span class="insight-chip">Records: ${scoped.length}</span>
                <span class="insight-chip">Total Forms: ${summaryTotal}</span>
                <span class="insight-chip">Avg / JFA: ${avgPerJfa}</span>
                <span class="insight-chip">Top JFA: ${topJfa.name || '—'} (${topJfa.value || 0})</span>
            </div>
        </div>
    `;

    const aggregated = new Map();
    todayRecords.forEach((record) => {
        if (isTeamLeaderName(record.name, record.team || '')) return;
        const key = normalizeJfaName(record.name);
        if (!key) return;
        const entry = aggregated.get(key) || { name: formatJfaName(record.name), team: record.team, forms: 0 };
        entry.forms += record.consentForms || 0;
        aggregated.set(key, entry);
    });
    const present = [...aggregated.values()].sort((a, b) => b.forms - a.forms);

    if (!present.length) {
        list.innerHTML = '<p class="menu-page-note">No check-ins for today yet.</p>';
        return;
    }

    list.innerHTML = present.map((entry) => {
        const status = entry.forms >= 4 ? 'over' : entry.forms >= 2 ? 'on' : 'under';
        const statusLabel = entry.forms >= 4 ? 'Over Performer' : entry.forms >= 2 ? 'On Target' : 'Under Performer';
        return `
            <div class="admin-jfa-card" data-source="admin" data-name="${escapeHtml(entry.name)}" onclick="openAdminJfaDetail('${escapeHtml(entry.name)}','admin')">
                <div>
                    <strong>${entry.name}</strong>
                    <div class="page-subtitle">${entry.team || '—'} • ${entry.forms} forms today</div>
                </div>
                <span class="admin-jfa-status ${status}">${statusLabel}</span>
            </div>
        `;
    }).join('');
    highlightInlineSelection('admin');
}

function openClientsAccessModal() {
    const modal = document.getElementById('clients-access-modal');
    const input = document.getElementById('clientsAccessPassword');
    if (!modal || !input) return;
    input.value = '';
    setModalError('', 'clientsAccessError');
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    setTimeout(() => input.focus(), 30);
}

function closeClientsAccessModal(success = false) {
    const modal = document.getElementById('clients-access-modal');
    if (modal) {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
    }
    setModalError('', 'clientsAccessError');
    if (pendingClientsAccessResolver) {
        pendingClientsAccessResolver(Boolean(success));
        pendingClientsAccessResolver = null;
    }
}

async function submitClientsAccessModal() {
    if (adminRole !== 'ADMIN') {
        setModalError('Admin access required.', 'clientsAccessError');
        return;
    }
    const input = document.getElementById('clientsAccessPassword');
    if (!input) return;
    const password = String(input.value || '').trim();
    if (!password) {
        setModalError('Password is required.', 'clientsAccessError');
        return;
    }
    const key = normalizeJfaName(appUser || '');
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!key || !account) {
        setModalError('Admin account not found.', 'clientsAccessError');
        return;
    }
    const valid = await verifyAndMigrateAccountPassword(account, password, accounts, key);
    if (!valid) {
        setModalError('Incorrect password.', 'clientsAccessError');
        input.select();
        return;
    }
    closeClientsAccessModal(true);
}

async function requireClientsPasswordGate() {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return false;
    }
    if (pendingClientsAccessResolver) return false;
    openClientsAccessModal();
    return new Promise((resolve) => {
        pendingClientsAccessResolver = resolve;
    });
}

async function openAdminMasterTab(tab) {
    const allowedTabs = new Set(['leads', 'facilities', 'jfas', 'fas', 'fasInRegister', 'teams', 'performance', 'clients', 'learning', 'forms']);
    const targetTab = allowedTabs.has(String(tab || '').trim()) ? tab : 'leads';
    if (targetTab === 'clients') {
        const ok = await requireClientsPasswordGate();
        if (!ok) return;
    }
    adminMasterTab = targetTab;
    renderAdminMasterLogger();
    updateAdminHeroTabButtons();
}

function isAdminStandaloneActive() {
    return document.getElementById('admin-standalone-page')?.classList.contains('active');
}

function getAdminMasterLoggerContainerId() {
    return isAdminStandaloneActive() ? 'adminStandaloneMasterLogger' : 'adminMasterLogger';
}

function getAdminFacilityDirectoryContainerId() {
    return isAdminStandaloneActive() ? 'adminStandaloneFacilityDirectory' : 'adminFacilityDirectory';
}

function renderAdminStandalonePage() {
    if (adminRole !== 'ADMIN') return;
    ensureAdminStandaloneButtons();
    renderTeamPortalButtons();
    const scope = document.getElementById('adminStandaloneScope');
    if (scope) scope.textContent = 'Scope: Admin (All)';
    updateAdminStandaloneHeroCounters();
    updateAdminHeroTabButtons();
    bindAdminHeroMetricInteractions();
    renderAdminMasterLogger();
    renderFacilityDirectory();
    renderAdminStandaloneInsights();
    requestAdminLiveRefresh();
}

function ensureAdminStandaloneButtons() {
    // Intentionally no-op: standalone admin buttons are controlled directly in HTML.
}

function bindAdminHeroMetricInteractions() {
    const cards = document.querySelectorAll('.admin-hero-stat[data-admin-metric]');
    cards.forEach((card) => {
        if (card.dataset.boundKeyMetric === '1') return;
        card.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            const metric = card.getAttribute('data-admin-metric') || '';
            if (!metric) return;
            openAdminHeroMetric(metric);
        });
        card.dataset.boundKeyMetric = '1';
    });
}

function buildAdminNeedsAssistanceItems() {
    const items = [];
    getAdminStandaloneTeams().forEach((team) => {
        const roster = buildTeamRoster(team);
        roster
            .filter((entry) => entry.needsAssistance)
            .forEach((entry) => {
                items.push({
                    name: entry.name,
                    team,
                    meta: `${team} • ${entry.riskMessage || 'Needs assistance'}`
                });
            });
    });
    return items.sort((a, b) => a.name.localeCompare(b.name));
}

function buildOpenInterventionItems() {
    const items = [];
    Object.entries(interventionLog || {}).forEach(([nameKey, entries]) => {
        if (!Array.isArray(entries) || entries.length === 0) return;
        const open = entries.filter((entry) => (entry?.status || 'Open') !== 'Closed');
        if (!open.length) return;
        const profile = jfaProfiles[nameKey] || {};
        const fallbackName = formatJfaName(profile.fullName || `${profile.name || ''} ${profile.surname || ''}`.trim() || nameKey);
        const team = profile.team || (open.find((item) => item?.team)?.team || '');
        items.push({
            name: fallbackName,
            team,
            meta: `${team || 'No Team'} • Open interventions: ${open.length}`
        });
    });
    return items.sort((a, b) => a.name.localeCompare(b.name));
}

function buildTodayFormsItems() {
    const today = todayKey();
    const map = new Map();
    const records = getScopedRecords().filter((record) => recordDateKey(record) === today);
    records.forEach((record) => {
        const key = normalizeJfaName(record.name);
        if (!key) return;
        const current = map.get(key) || { name: formatJfaName(record.name), team: record.team || '', forms: 0, leads: 0 };
        current.forms += Number(record.consentForms || 0);
        if (!current.team && record.team) current.team = record.team;
        map.set(key, current);
    });
    leadRecords
        .filter((lead) => lead?.timestamp && dateKeyLocal(new Date(lead.timestamp)) === today)
        .forEach((lead) => {
            const key = normalizeJfaName(lead.jfaName);
            if (!key) return;
            const current = map.get(key) || { name: formatJfaName(lead.jfaName || key), team: lead.jfaTeam || '', forms: 0, leads: 0 };
            current.leads += 1;
            if (!current.team && lead.jfaTeam) current.team = lead.jfaTeam;
            map.set(key, current);
        });
    return [...map.values()]
        .sort((a, b) => (b.forms + b.leads) - (a.forms + a.leads) || a.name.localeCompare(b.name))
        .map((entry) => ({
            name: entry.name,
            team: entry.team,
            meta: `${entry.team || 'No Team'} • Forms: ${entry.forms} • Leads: ${entry.leads}`
        }));
}

function openAdminHeroMetric(metric) {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    const key = String(metric || '').trim();
    if (key === 'totalLeads') {
        clearAdminLeadFilters();
        openAdminStandaloneTab('leads');
        return;
    }
    if (key === 'pendingLeads') {
        openAdminPaymentsFromStandalone();
        setPaymentsTab('pending');
        return;
    }
    if (key === 'jfas') {
        openAdminStandaloneTab('jfas');
        return;
    }
    if (key === 'fasInRegister') {
        openAdminStandaloneTab('fasInRegister');
        return;
    }
    if (key === 'facilities') {
        openAdminStandaloneTab('facilities');
        return;
    }
    if (key === 'needsAssist') {
        const items = buildAdminNeedsAssistanceItems();
        openHeroListModal('Needs Assistance', items);
        return;
    }
    if (key === 'openInterventions') {
        const items = buildOpenInterventionItems();
        openHeroListModal('Open Interventions', items);
        return;
    }
    if (key === 'formsToday') {
        const items = buildTodayFormsItems();
        openHeroListModal('Forms Today', items);
    }
}

async function openAdminStandaloneTab(tab) {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    const allowedTabs = new Set(['leads', 'facilities', 'jfas', 'fas', 'fasInRegister', 'teams', 'performance', 'clients', 'learning', 'forms']);
    const targetTab = allowedTabs.has(String(tab || '').trim()) ? tab : 'leads';
    if (targetTab === 'clients') {
        const ok = await requireClientsPasswordGate();
        if (!ok) return;
    }
    adminMasterTab = targetTab;
    renderAdminStandalonePage();
    document.getElementById('adminStandaloneMasterLogger')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openTeamPortalFromAdminStandalone(teamName) {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    if (!teamName) return;
    openTeamDetailPage(teamName, true);
}

function openAdminMenuStatsFromStandalone() {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    openMenuPage('admin', true, true);
}

function openAdminPaymentsFromStandalone() {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    openMenuPage('payments', true, true);
}

function openAdminSettingsFromStandalone() {
    if (adminRole !== 'ADMIN') {
        showToast('Admin access required.', 'error');
        return;
    }
    openMenuPage('settings', true, true);
}

function getAdminStandaloneTeams() {
    const teams = new Set();
    if (typeof getAllTeams === 'function') {
        getAllTeams().forEach((team) => {
            if (team) teams.add(team);
        });
    }
    jfaRecords.forEach((record) => {
        if (record?.team) teams.add(record.team);
    });
    Object.values(jfaProfiles || {}).forEach((profile) => {
        if (profile?.team) teams.add(profile.team);
    });
    return [...teams].sort((a, b) => a.localeCompare(b));
}

function renderAdminStandaloneInsights() {
    const needsAssistEl = document.getElementById('adminHeroNeedsAssist');
    const openInterventionsEl = document.getElementById('adminHeroOpenInterventions');
    const todayFormsEl = document.getElementById('adminHeroTodayForms');
    const healthEl = document.getElementById('adminStandaloneHealth');
    const activityEl = document.getElementById('adminStandaloneRecentActivity');

    const now = new Date();
    const startToday = getStartOfDay(now);
    const todayRecords = getScopedRecordsByRange(startToday, now);
    const todayForms = todayRecords.reduce((sum, record) => sum + (record.consentForms || 0), 0) + leadRecords.filter((lead) => {
        if (!lead?.timestamp) return false;
        return dateKeyLocal(new Date(lead.timestamp)) === todayKey();
    }).length;

    let needsAssist = 0;
    getAdminStandaloneTeams().forEach((team) => {
        const roster = buildTeamRoster(team);
        needsAssist += roster.filter((entry) => entry.needsAssistance).length;
    });

    const openInterventions = Object.values(interventionLog || {}).reduce((sum, entries) => {
        if (!Array.isArray(entries)) return sum;
        return sum + entries.filter((entry) => (entry?.status || 'Open') !== 'Closed').length;
    }, 0);

    if (needsAssistEl) needsAssistEl.textContent = String(needsAssist);
    if (openInterventionsEl) openInterventionsEl.textContent = String(openInterventions);
    if (todayFormsEl) todayFormsEl.textContent = String(todayForms);

    if (healthEl) {
        const accounts = getUserAccounts();
        const users = Object.values(accounts || {});
        const activeUsers = users.filter((user) => user && user.active !== false).length;
        const hashedUsers = users.filter((user) => user && user.passwordHash && user.passwordSalt).length;
        const pendingLeads = leadRecords.filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Pending').length;
        healthEl.innerHTML = `
            <span class="insight-chip">Active Users: ${activeUsers}</span>
            <span class="insight-chip">Secured Passwords: ${hashedUsers}/${users.length || 0}</span>
            <span class="insight-chip">Pending Leads: ${pendingLeads}</span>
            <span class="insight-chip ${needsAssist ? 'danger' : ''}">At-Risk JFAs: ${needsAssist}</span>
            <span class="insight-chip ${openInterventions ? 'danger' : ''}">Open Interventions: ${openInterventions}</span>
        `;
    }

    if (activityEl) {
        const raw = JSON.parse(localStorage.getItem(STORAGE_KEYS.auditLog) || '[]');
        const log = Array.isArray(raw) ? raw : [];
        if (!log.length) {
            activityEl.innerHTML = '<p class="no-data">No admin activity yet.</p>';
        } else {
            activityEl.innerHTML = log.slice(0, 10).map((entry) => {
                const time = entry?.time ? new Date(entry.time).toLocaleString('en-ZA') : '—';
                const action = escapeHtml(entry?.action || 'Activity');
                const details = escapeHtml(entry?.details || '');
                return `<div class="audit-item">${time} • ${action}${details ? ` • ${details}` : ''}</div>`;
            }).join('');
        }
    }
}

function updateAdminHeroTabButtons() {
    const tabs = {
        leads: document.getElementById('adminHeroTabLeads'),
        facilities: document.getElementById('adminHeroTabFacilities'),
        jfas: document.getElementById('adminHeroTabJfas'),
        fas: document.getElementById('adminHeroTabFas'),
        fasInRegister: document.getElementById('adminHeroTabFasInRegister'),
        teams: document.getElementById('adminHeroTabTeams'),
        performance: document.getElementById('adminHeroTabPerformance'),
        clients: document.getElementById('adminHeroTabClients'),
        learning: document.getElementById('adminHeroTabLearning'),
        forms: document.getElementById('adminHeroTabForms')
    };
    Object.entries(tabs).forEach(([key, btn]) => {
        if (!btn) return;
        const active = adminMasterTab === key;
        btn.classList.toggle('secondary', !active);
        btn.classList.toggle('admin-tab-active', active);
    });
}

function getCompanyJfaDirectory() {
    const accounts = getUserAccounts();
    const isExcludedFromJfaRegister = (rawKey) => {
        const key = normalizeJfaName(rawKey || '');
        if (!key) return true;
        if (key === 'admin') return true;
        const account = accounts[key];
        if (!account) return false;
        const perms = normalizeUserPermissions(account.permissions, key === 'admin');
        return account.adminOnly === true || perms.admin === true;
    };
    const map = new Map();
    const allRecords = [...getArchiveRangeRecords(new Date('2000-01-01'), new Date()), ...jfaRecords];
    allRecords.forEach((record) => {
        if (!record?.name) return;
        const key = normalizeJfaName(record.name);
        if (isExcludedFromJfaRegister(key)) return;
        const current = map.get(key) || {
            name: formatJfaName(record.name),
            team: record.team || '',
            phone: record.phone || '',
            lastSeen: record.timestamp || '',
            presentToday: false
        };
        if (record.timestamp && (!current.lastSeen || record.timestamp > current.lastSeen)) {
            current.lastSeen = record.timestamp;
            current.team = record.team || current.team;
            current.phone = record.phone || current.phone;
        }
        map.set(key, current);
    });
    Object.entries(jfaProfiles).forEach(([key, profile]) => {
        if (!key || archivedJfaNames.has(key) || isExcludedFromJfaRegister(key)) return;
        const existing = map.get(key) || {
            name: formatJfaName(profile?.fullName || `${profile?.name || ''} ${profile?.surname || ''}`.trim() || key),
            team: '',
            phone: '',
            lastSeen: '',
            presentToday: false
        };
        existing.name = formatJfaName(profile?.fullName || existing.name || key);
        existing.team = profile?.team || existing.team || '';
        existing.phone = profile?.phone || existing.phone || '';
        map.set(key, existing);
    });
    const today = todayKey();
    jfaRecords.forEach((record) => {
        if (!record?.name) return;
        const key = normalizeJfaName(record.name);
        if (isExcludedFromJfaRegister(key)) return;
        const item = map.get(key);
        if (!item) return;
        if (recordDateKey(record) === today) item.presentToday = true;
    });
    return [...map.entries()]
        .filter(([key]) => key && !isExcludedFromJfaRegister(key) && !archivedJfaNames.has(key))
        .map(([key, value]) => ({ key, ...value }))
        .sort((a, b) => a.name.localeCompare(b.name));
}

function getFaRegisterDirectory() {
    // FA Register is FA-only by design.
    // Do not merge regular user/JFA accounts into this directory.
    return Object.entries(faProfiles || {})
        .filter(([key, profile]) => Boolean(key && profile))
        .map(([key, profile]) => ({
            key,
            name: formatJfaName(profile.fullName || `${profile.name || ''} ${profile.surname || ''}`.trim() || key),
            username: profile.username || key,
            email: profile.email || '',
            phone: profile.phone || '',
            team: profile.team || '',
            active: String(profile.status || 'Active').toLowerCase() !== 'inactive',
            status: profile.status || 'Active',
            createdAt: profile.createdAt || '',
            updatedAt: profile.updatedAt || '',
            hasProfile: true
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
}

function renderAdminMasterLogger() {
    const container = document.getElementById(getAdminMasterLoggerContainerId());
    if (!container) return;
    if (adminRole !== 'ADMIN') {
        container.innerHTML = '';
        return;
    }
    const isLeads = adminMasterTab === 'leads';
    const isFacilities = adminMasterTab === 'facilities';
    const isJfas = adminMasterTab === 'jfas';
    const isFas = adminMasterTab === 'fas';
    const isFasInRegister = adminMasterTab === 'fasInRegister';
    const isTeams = adminMasterTab === 'teams';
    const isPerformance = adminMasterTab === 'performance';
    const isClients = adminMasterTab === 'clients';
    const isLearning = adminMasterTab === 'learning';
    const isForms = adminMasterTab === 'forms';
    container.innerHTML = `
        <div class="insight-card">
            <h4>Master Logger (Admin All)</h4>
            <p class="page-subtitle">Full control center: submitted leads, facility editor, JFA register editor, learning updates, and forms library.</p>
            <div class="menu-page-actions">
                <button class="action-btn ${isLeads ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('leads')">Submitted Leads</button>
                <button class="action-btn ${isFacilities ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('facilities')">Edit Facilities</button>
                <button class="action-btn ${isJfas ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('jfas')">JFA Register</button>
                <button class="action-btn ${isFas ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('fas')">FA Register</button>
                <button class="action-btn ${isTeams ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('teams')">Team Leaders</button>
                <button class="action-btn ${isPerformance ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('performance')">Performance Review</button>
                <button class="action-btn ${isClients ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('clients')">Clients (Secure)</button>
                <button class="action-btn ${isLearning ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('learning')">Learning Hub</button>
                <button class="action-btn ${isForms ? '' : 'secondary'}" type="button" onclick="openAdminMasterTab('forms')">Forms Library</button>
                <button class="action-btn secondary" type="button" onclick="openNotificationComposeModal('ALL')">Send Notification</button>
            </div>
            <div id="adminMasterBody"></div>
        </div>
    `;
    const body = document.getElementById('adminMasterBody');
    if (!body) return;
    if (isFacilities) {
        body.innerHTML = renderMasterFacilitiesEditor();
    } else if (isJfas) {
        body.innerHTML = renderMasterJfaRegisterEditor();
    } else if (isFas) {
        body.innerHTML = renderMasterFaRegister();
    } else if (isFasInRegister) {
        body.innerHTML = renderMasterFasInRegister();
    } else if (isTeams) {
        body.innerHTML = renderMasterTeamLeaderManager();
    } else if (isPerformance) {
        body.innerHTML = renderMasterPerformanceReview();
    } else if (isClients) {
        body.innerHTML = renderMasterClientsRegistry();
    } else if (isLearning) {
        body.innerHTML = renderMasterLearningEditor();
    } else if (isForms) {
        body.innerHTML = renderMasterFormsEditor();
    } else {
        body.innerHTML = renderMasterSubmittedLeads();
    }
    if (isLearning) {
        loadMasterLearningTopic();
    }
    bindPasswordStrengthIndicators(document);
}

function renderMasterFaRegister() {
    const fas = getFaRegisterDirectory();
    return `
        <div class="insight-card">
            <h4>FA Register (All)</h4>
            <p class="page-subtitle">Admin (All) captures and maintains all Financial Advisor records, including banking and compliance details.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="faCaptureName">Full Name</label>
                    <input type="text" id="faCaptureName" placeholder="e.g. John Doe">
                </div>
                <div class="form-group">
                    <label for="faCaptureTeam">Team</label>
                    <input type="text" id="faCaptureTeam" placeholder="e.g. Team Thato">
                </div>
                <div class="form-group">
                    <label for="faCaptureUsername">Username</label>
                    <input type="text" id="faCaptureUsername" placeholder="e.g. john.doe">
                </div>
                <div class="form-group">
                    <label for="faCapturePhone">Phone</label>
                    <input type="text" id="faCapturePhone" placeholder="e.g. 0812345678">
                </div>
                <div class="form-group">
                    <label for="faCaptureEmail">Email</label>
                    <input type="email" id="faCaptureEmail" placeholder="e.g. john@matla.co.za">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="captureMasterFaRecord()">Capture FA Record</button>
                <button class="action-btn secondary" type="button" onclick="exportMasterFaRegister()">Download FA Register</button>
                <button class="action-btn secondary" type="button" onclick="toggleAllRegisterAccountAccess('fa', true)">Enable All FAs</button>
                <button class="action-btn secondary" type="button" onclick="toggleAllRegisterAccountAccess('fa', false)">Disable All FAs</button>
            </div>
            <div class="insight-list">
                <span class="insight-chip">Total FAs: ${fas.length}</span>
                <span class="insight-chip">Active: ${fas.filter((fa) => fa.active).length}</span>
                <span class="insight-chip">Inactive: ${fas.filter((fa) => !fa.active).length}</span>
            </div>
            ${fas.length ? `
                <div class="admin-jfa-list" style="margin-top:12px;">
                    ${fas.map((fa) => `
                        <div class="admin-jfa-card" onclick="openMasterFaProfile('${escapeHtml(fa.key)}')">
                            <div>
                                <strong>${escapeHtml(fa.name || '—')}</strong>
                                <div class="page-subtitle">${escapeHtml(fa.team || 'No Team')} • ${escapeHtml(fa.username || '—')}</div>
                            </div>
                            <div style="display:grid; gap:8px; justify-items:end;">
                                <span class="admin-jfa-status ${fa.active ? 'on' : 'under'}">${escapeHtml(fa.status || (fa.active ? 'Active' : 'Inactive'))}</span>
                                ${renderRegisterAccountAccessSwitch('fa', fa.key, fa.name, fa.username, fa.email)}
                            </div>
                        </div>
                    `).join('')}
                </div>
                <div class="mini-table" style="margin-top:12px;">
                    <table>
                        <thead>
                            <tr>
                                <th>FA Name</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Phone</th>
                                <th>Team</th>
                                <th>Status</th>
                                <th>Login Access</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${fas.map((fa) => `
                                <tr>
                                    <td>${escapeHtml(fa.name || '—')}</td>
                                    <td>${escapeHtml(fa.username || '—')}</td>
                                    <td>${escapeHtml(fa.email || '—')}</td>
                                    <td>${escapeHtml(fa.phone || '—')}</td>
                                    <td>${escapeHtml(fa.team || '—')}</td>
                                    <td>${escapeHtml(fa.status || (fa.active ? 'Active' : 'Inactive'))}</td>
                                    <td>${renderRegisterAccountAccessSwitch('fa', fa.key, fa.name, fa.username, fa.email)}</td>
                                    <td>${fa.createdAt ? new Date(fa.createdAt).toLocaleString('en-ZA') : '—'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle" style="margin-top:10px;">No FA records found yet.</p>'}
            <div class="admin-detail-section" id="masterFaProfileDetail"></div>
        </div>
    `;
}

function renderMasterPerformanceReview() {
    const teams = getAllTeams();
    const rows = teams.flatMap((teamName) => buildTeamRoster(teamName))
        .filter((entry) => !entry.isTeamLeader)
        .map((entry) => ({
            name: entry.name,
            team: entry.team || '—',
            monthForms: Number(entry.formsMonth || 0),
            todayForms: Number(entry.formsToday || 0),
            underStreak: Number(entry.underStreak || 0),
            status: entry.performanceLabel || (entry.monthForms < 20 ? 'Under Performing' : 'Performing'),
            needsAssistance: Boolean(entry.needsAssistance),
            openInterventions: Number(entry.openInterventions || 0)
        }))
        .filter((entry) => entry.monthForms < 20)
        .sort((a, b) => {
            if (a.monthForms !== b.monthForms) return a.monthForms - b.monthForms;
            return b.underStreak - a.underStreak;
        });

    const critical = rows.filter((r) => r.needsAssistance || r.underStreak >= 3).length;
    return `
        <div class="insight-card">
            <h4>Performance Review</h4>
            <p class="page-subtitle">JFAs below monthly threshold (20 consent forms/leads) are listed for intervention support.</p>
            <div class="insight-list">
                <span class="insight-chip">Underperforming JFAs: ${rows.length}</span>
                <span class="insight-chip ${critical ? 'danger' : ''}">Critical Cases: ${critical}</span>
            </div>
            ${rows.length ? `
                <div class="mini-table admin-performance-review-table-wrap" style="margin-top:12px;">
                    <table class="performance-review-table mobile-stack-table">
                        <thead>
                            <tr>
                                <th>JFA Name</th>
                                <th>Team</th>
                                <th>Month Total</th>
                                <th>Today</th>
                                <th>Underperform Streak</th>
                                <th>Status</th>
                                <th>Open Interventions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows.map((entry) => `
                                <tr>
                                    <td data-label="JFA Name">${escapeHtml(entry.name)}</td>
                                    <td data-label="Team">${escapeHtml(entry.team)}</td>
                                    <td data-label="Month Total"><strong>${entry.monthForms}</strong></td>
                                    <td data-label="Today">${entry.todayForms}</td>
                                    <td data-label="Underperform Streak">${entry.underStreak} day(s)</td>
                                    <td data-label="Status"><span class="admin-jfa-status ${entry.needsAssistance ? 'under' : 'on'}">${escapeHtml(entry.status)}</span></td>
                                    <td data-label="Open Interventions">${entry.openInterventions}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle" style="margin-top:10px;">No underperforming JFAs this month.</p>'}
        </div>
    `;
}

function getTodayFaAttendanceRows() {
    const today = todayKey();
    const map = new Map();
    (Array.isArray(faAttendanceRecords) ? faAttendanceRecords : [])
        .filter((item) => String(item?.dateKey || '') === today)
        .forEach((item) => {
            const name = formatJfaName(item?.name || '');
            if (!name) return;
            const key = normalizeJfaName(name);
            if (!key) return;
            const profile = faProfiles[key] || ensureFaProfile(name) || {};
            const existing = map.get(key);
            const entry = {
                key,
                name,
                team: String(item?.team || profile.team || '').trim(),
                email: String(profile.email || '').trim(),
                phone: String(profile.phone || '').trim(),
                timestamp: String(item?.timestamp || '')
            };
            if (!existing || (entry.timestamp && entry.timestamp > existing.timestamp)) {
                map.set(key, entry);
            }
        });
    return [...map.values()].sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
}

function renderMasterFasInRegister() {
    const rows = getTodayFaAttendanceRows();
    return `
        <div class="insight-card">
            <h4>FAs In Register (Today)</h4>
            <p class="page-subtitle">Live list of Financial Advisors marked present today.</p>
            <div class="insight-list">
                <span class="insight-chip">Present FAs Today: ${rows.length}</span>
            </div>
            <div class="menu-page-actions" style="margin-top:10px;">
                <button class="action-btn secondary" type="button" onclick="exportFasInRegisterCsv()">Download CSV</button>
            </div>
            ${rows.length ? `
                <div class="mini-table" style="margin-top:12px;">
                    <table>
                        <thead>
                            <tr>
                                <th>FA Name</th>
                                <th>Team</th>
                                <th>Email</th>
                                <th>Phone</th>
                                <th>Marked Present At</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows.map((row) => `
                                <tr>
                                    <td>${escapeHtml(row.name || '—')}</td>
                                    <td>${escapeHtml(row.team || '—')}</td>
                                    <td>${escapeHtml(row.email || '—')}</td>
                                    <td>${escapeHtml(row.phone || '—')}</td>
                                    <td>${row.timestamp ? new Date(row.timestamp).toLocaleString('en-ZA') : '—'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle" style="margin-top:10px;">No FAs marked present today yet.</p>'}
        </div>
    `;
}

function exportFasInRegisterCsv() {
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can export FAs In Register.', 'error');
        return;
    }
    const rows = getTodayFaAttendanceRows();
    if (!rows.length) {
        showToast('No FAs in register for today.', 'error');
        return;
    }
    const headers = ['FA Name', 'Team', 'Email', 'Phone', 'Marked Present At'];
    const data = rows.map((row) => [
        row.name || '',
        row.team || '',
        row.email || '',
        row.phone || '',
        row.timestamp ? new Date(row.timestamp).toLocaleString('en-ZA') : ''
    ]);
    exportCsvWithHeaders(headers, data, `fas-in-register-${todayKey()}.csv`, 'FAs In Register Export');
    logAudit('Exported FAs In Register', `Rows: ${data.length}`);
    logExportHistory('FAs In Register Export', data.length);
}

function resolveLinkedRegisterAccountKey({ key = '', name = '', username = '', email = '' } = {}) {
    const accounts = getUserAccounts();
    const candidates = [];
    const add = (value) => {
        const normalized = normalizeJfaName(value || '');
        if (!normalized || normalized === 'admin') return;
        if (!candidates.includes(normalized)) candidates.push(normalized);
    };
    add(key);
    add(username);
    add(name);
    const emailLower = String(email || '').trim().toLowerCase();
    if (emailLower) {
        const match = Object.entries(accounts).find(([, account]) => String(account?.email || '').trim().toLowerCase() === emailLower);
        if (match?.[0]) add(match[0]);
    }
    return candidates.find((candidate) => Boolean(accounts[candidate])) || '';
}

function renderRegisterAccountAccessSwitch(kind, rawKey, name = '', username = '', email = '') {
    const accountKey = resolveLinkedRegisterAccountKey({ key: rawKey, name, username, email });
    if (!accountKey) return '<span class="page-subtitle">No login account</span>';
    const account = getUserAccounts()[accountKey];
    if (!account) return '<span class="page-subtitle">No login account</span>';
    const enabled = account.active !== false;
    const encodedKey = encodeURIComponent(String(rawKey || ''));
    return `
        <span class="toggle-row" onclick="event.stopPropagation();" title="Enable or disable system login access">
            <label class="switch">
                <input type="checkbox" ${enabled ? 'checked' : ''} onchange="toggleRegisterAccountAccess('${kind}','${encodedKey}', this.checked, event)">
                <span class="slider"></span>
            </label>
        </span>
    `;
}

function toggleRegisterAccountAccess(kind, encodedKey, shouldEnable, event) {
    if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can change account access.', 'error');
        renderAdminMasterLogger();
        return;
    }
    const rawKey = decodeURIComponent(String(encodedKey || ''));
    let details = { key: rawKey };
    if (kind === 'fa') {
        const fa = getFaRegisterDirectory().find((entry) => String(entry.key || '') === rawKey);
        if (fa) details = { key: fa.key, name: fa.name, username: fa.username, email: fa.email };
    } else if (kind === 'jfa') {
        const jfa = getCompanyJfaDirectory().find((entry) => String(entry.key || '') === rawKey);
        if (jfa) details = { key: jfa.key, name: jfa.name, username: '', email: '' };
    }
    const accountKey = resolveLinkedRegisterAccountKey(details);
    if (!accountKey) {
        showToast('No linked login account found.', 'error');
        renderAdminMasterLogger();
        return;
    }
    if (accountKey === normalizeJfaName(appUser || '')) {
        showToast('You cannot disable the account currently logged in.', 'error');
        renderAdminMasterLogger();
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[accountKey];
    if (!account) {
        showToast('Account not found.', 'error');
        renderAdminMasterLogger();
        return;
    }
    account.active = Boolean(shouldEnable);
    account.updatedAt = new Date().toISOString();
    account.updatedBy = formatJfaName(appUser || 'admin');
    accounts[accountKey] = account;
    saveUserAccounts(accounts);
    const label = formatJfaName(account.username || accountKey);
    logUserMgmtAction(account.active ? 'Account enabled (register switch)' : 'Account disabled (register switch)', `Account: ${label}`);
    logAudit(account.active ? 'Account enabled' : 'Account disabled', `${label} • source: ${kind === 'fa' ? 'FA Register' : 'JFA Register'}`);
    showToast(`${label} ${account.active ? 'enabled' : 'disabled'}.`, 'success');
    renderAdminMasterLogger();
}

function getRegisterAccountAccessTargets(kind) {
    const rows = kind === 'fa' ? getFaRegisterDirectory() : getCompanyJfaDirectory();
    const targets = [];
    rows.forEach((entry) => {
        const accountKey = resolveLinkedRegisterAccountKey({
            key: entry?.key || '',
            name: entry?.name || '',
            username: entry?.username || '',
            email: entry?.email || ''
        });
        if (!accountKey) return;
        if (!targets.includes(accountKey)) targets.push(accountKey);
    });
    return targets;
}

async function toggleAllRegisterAccountAccess(kind, shouldEnable) {
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can change account access.', 'error');
        return;
    }
    const normalizedKind = kind === 'fa' ? 'fa' : 'jfa';
    const subject = normalizedKind === 'fa' ? 'FAs' : 'JFAs';
    const targets = getRegisterAccountAccessTargets(normalizedKind);
    if (!targets.length) {
        showToast(`No linked ${subject} login accounts found.`, 'error');
        return;
    }
    const confirm = await openAppConfirmModal({
        title: `${shouldEnable ? 'Enable' : 'Disable'} All ${subject}`,
        message: `This will ${shouldEnable ? 'enable' : 'disable'} login access for all linked ${subject} accounts${shouldEnable ? '' : ' (except your current account)'} . Continue?`,
        confirmText: shouldEnable ? `Enable ${subject}` : `Disable ${subject}`,
        cancelText: 'Cancel'
    });
    if (!confirm) return;

    const accounts = getUserAccounts();
    const currentKey = normalizeJfaName(appUser || '');
    let changed = 0;
    let skippedSelf = 0;

    targets.forEach((accountKey) => {
        const account = accounts[accountKey];
        if (!account) return;
        if (!shouldEnable && accountKey === currentKey) {
            skippedSelf += 1;
            return;
        }
        const nextState = Boolean(shouldEnable);
        if (account.active === nextState) return;
        account.active = nextState;
        account.updatedAt = new Date().toISOString();
        account.updatedBy = formatJfaName(appUser || 'admin');
        accounts[accountKey] = account;
        changed += 1;
    });

    saveUserAccounts(accounts);
    logUserMgmtAction(
        shouldEnable ? `Bulk enable ${subject}` : `Bulk disable ${subject}`,
        `Changed: ${changed}${skippedSelf ? ` • skipped self: ${skippedSelf}` : ''}`
    );
    logAudit(
        shouldEnable ? 'Bulk account enable' : 'Bulk account disable',
        `${subject} • changed: ${changed}${skippedSelf ? ` • skipped self: ${skippedSelf}` : ''}`
    );
    showToast(
        `${subject} updated. ${changed} account${changed === 1 ? '' : 's'} changed${skippedSelf ? `, ${skippedSelf} skipped` : ''}.`,
        changed ? 'success' : 'error'
    );
    renderAdminMasterLogger();
}

function captureMasterFaRecord() {
    if (adminRole !== 'ADMIN') return;
    const nameEl = document.getElementById('faCaptureName');
    const teamEl = document.getElementById('faCaptureTeam');
    const userEl = document.getElementById('faCaptureUsername');
    const phoneEl = document.getElementById('faCapturePhone');
    const emailEl = document.getElementById('faCaptureEmail');
    if (!nameEl || !teamEl || !userEl || !phoneEl || !emailEl) return;
    const fullName = formatJfaName(nameEl.value || '');
    const team = (teamEl.value || '').trim();
    const username = normalizeJfaName((userEl.value || '').trim() || fullName);
    const phone = (phoneEl.value || '').trim();
    const email = (emailEl.value || '').trim().toLowerCase();
    if (!fullName) {
        showToast('FA full name is required.', 'error');
        nameEl.focus();
        return;
    }
    if (email && !isValidEmail(email)) {
        showToast('Please enter a valid email address.', 'error');
        emailEl.focus();
        return;
    }
    const key = normalizeJfaName(fullName);
    const profile = ensureFaProfile(fullName, { team, username, phone, email, status: 'Active' }) || {};
    profile.fullName = fullName;
    profile.username = username || profile.username || key;
    if (team) profile.team = team;
    if (phone) profile.phone = phone;
    if (email) profile.email = email;
    profile.status = 'Active';
    profile.updatedAt = new Date().toISOString();
    if (!profile.createdAt) profile.createdAt = profile.updatedAt;
    faProfiles[key] = profile;
    saveFaProfiles();
    logAudit('Master Logger captured FA', `${fullName} (${team || 'No Team'})`);
    nameEl.value = '';
    teamEl.value = '';
    userEl.value = '';
    phoneEl.value = '';
    emailEl.value = '';
    renderAdminMasterLogger();
    showToast('FA captured in register.', 'success');
}

function openMasterFaProfile(faKey) {
    if (adminRole !== 'ADMIN') return;
    const detail = document.getElementById('masterFaProfileDetail');
    if (!detail) return;
    const key = normalizeJfaName(faKey || '');
    const current = faProfiles[key];
    if (!current) {
        showToast('FA profile not found.', 'error');
        return;
    }
    const fullName = formatJfaName(current.fullName || `${current.name || ''} ${current.surname || ''}`.trim() || key);
    const profile = ensureFaProfile(fullName, { team: current.team || '', username: current.username || key }) || {};
    saveFaProfiles();
    detail.innerHTML = `
        <div class="insight-card">
            <h4>${escapeHtml(fullName)} • FA Personal Info</h4>
            <p class="page-subtitle">Capture and maintain full FA details. Only Admin (All) can edit this section.</p>
            <div class="mini-table master-file-table">
                <table>
                    <tbody>
                        ${renderProfileSectionRow('Personal Details')}
                        ${renderProfileFieldRow('Name', `fp-name-${key}`, profile.name)}
                        ${renderProfileFieldRow('Surname', `fp-surname-${key}`, profile.surname)}
                        ${renderProfileFieldRow('Username', `fp-username-${key}`, profile.username || key)}
                        ${renderProfileFieldRow('Team', `fp-team-${key}`, profile.team)}
                        ${renderProfileFieldRow('Status (Active / Inactive)', `fp-status-${key}`, profile.status || 'Active')}
                        ${renderProfileSectionRow('Contact Details')}
                        ${renderProfileFieldRow('Phone Number', `fp-phone-${key}`, profile.phone)}
                        ${renderProfileFieldRow('Email', `fp-email-${key}`, profile.email)}
                        ${renderProfileSectionRow('Address')}
                        ${renderProfileFieldRow('Physical Address', `fp-address-${key}`, profile.address)}
                        ${renderProfileSectionRow('Banking Details')}
                        ${renderProfileFieldRow('Bank Name', `fp-bank-${key}`, profile.bankName)}
                        ${renderProfileFieldRow('Account Number', `fp-account-${key}`, profile.accountNumber)}
                        ${renderProfileFieldRow('Branch Code', `fp-branch-${key}`, profile.branchCode)}
                        ${renderProfileSectionRow('Compliance')}
                        ${renderProfileFieldRow('Tax Number', `fp-tax-${key}`, profile.taxNumber)}
                        ${renderProfileSectionRow('Next of Kin')}
                        ${renderProfileFieldRow('Next of Kin Name', `fp-nok-name-${key}`, profile.nextOfKinName)}
                        ${renderProfileFieldRow('Next of Kin Phone', `fp-nok-phone-${key}`, profile.nextOfKinPhone)}
                        ${renderProfileFieldRow('Relationship', `fp-nok-rel-${key}`, profile.nextOfKinRelationship)}
                    </tbody>
                </table>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveMasterFaProfile('${escapeHtml(key)}')">Capture</button>
                <button class="action-btn secondary" type="button" onclick="exportMasterFaProfile('${escapeHtml(key)}')">Download FA Record</button>
            </div>
        </div>
    `;
}

function saveMasterFaProfile(faKey) {
    if (adminRole !== 'ADMIN') return;
    const key = normalizeJfaName(faKey || '');
    const current = faProfiles[key];
    if (!current) return;
    const read = (suffix) => document.getElementById(`fp-${suffix}-${key}`)?.value?.trim() || '';
    const fullName = formatJfaName(`${read('name')} ${read('surname')}`.trim() || current.fullName || key);
    const profile = ensureFaProfile(fullName, { username: read('username') || current.username || key }) || {};
    profile.name = read('name');
    profile.surname = read('surname');
    profile.fullName = fullName;
    profile.username = normalizeJfaName(read('username') || profile.username || key);
    profile.team = read('team');
    profile.status = read('status') || profile.status || 'Active';
    profile.phone = read('phone');
    profile.email = read('email');
    profile.address = read('address');
    profile.bankName = read('bank');
    profile.accountNumber = read('account');
    profile.branchCode = read('branch');
    profile.taxNumber = read('tax');
    profile.nextOfKinName = read('nok-name');
    profile.nextOfKinPhone = read('nok-phone');
    profile.nextOfKinRelationship = read('nok-rel');
    profile.updatedAt = new Date().toISOString();
    if (!profile.createdAt) profile.createdAt = profile.updatedAt;
    faProfiles[key] = profile;
    saveFaProfiles();
    logAudit('Master Logger captured FA profile', `${fullName} profile captured`);
    showToast('FA profile captured and saved.', 'success');
    renderAdminMasterLogger();
}

function exportMasterFaProfile(faKey) {
    if (adminRole !== 'ADMIN') return;
    const key = normalizeJfaName(faKey || '');
    const profile = faProfiles[key];
    if (!profile) {
        showToast('FA profile not found.', 'error');
        return;
    }
    const fullName = formatJfaName(profile.fullName || `${profile.name || ''} ${profile.surname || ''}`.trim() || key);
    const headers = [
        'Full Name',
        'Name',
        'Surname',
        'Username',
        'Team',
        'Status',
        'Phone Number',
        'Email Address',
        'Physical Address',
        'Bank Name',
        'Account Number',
        'Branch Code',
        'Tax Number',
        'Next of Kin Name',
        'Next of Kin Phone',
        'Next of Kin Relationship'
    ];
    const rows = [[
        fullName,
        profile.name || '',
        profile.surname || '',
        profile.username || '',
        profile.team || '',
        profile.status || 'Active',
        profile.phone || '',
        profile.email || '',
        profile.address || '',
        profile.bankName || '',
        profile.accountNumber || '',
        profile.branchCode || '',
        profile.taxNumber || '',
        profile.nextOfKinName || '',
        profile.nextOfKinPhone || '',
        profile.nextOfKinRelationship || ''
    ]];
    exportCsvWithHeaders(headers, rows, `fa-profile-${key || 'record'}.csv`);
    logAudit('Exported FA profile', `${fullName}`);
    logExportHistory(`FA Profile Export: ${fullName}`, rows.length);
}

function exportMasterFaRegister() {
    if (adminRole !== 'ADMIN') return;
    const rows = getFaRegisterDirectory().map((entry) => {
        const profile = faProfiles[entry.key] || {};
        return [
            entry.name || '',
            entry.username || '',
            profile.team || entry.team || '',
            profile.status || entry.status || (entry.active ? 'Active' : 'Inactive'),
            profile.phone || entry.phone || '',
            profile.email || entry.email || '',
            profile.address || '',
            profile.bankName || '',
            profile.accountNumber || '',
            profile.branchCode || '',
            profile.taxNumber || '',
            profile.nextOfKinName || '',
            profile.nextOfKinPhone || '',
            profile.nextOfKinRelationship || '',
            profile.createdAt || entry.createdAt || '',
            profile.updatedAt || entry.updatedAt || ''
        ];
    });
    const headers = [
        'FA Name',
        'Username',
        'Team',
        'Status',
        'Phone',
        'Email',
        'Address',
        'Bank Name',
        'Account Number',
        'Branch Code',
        'Tax Number',
        'Next of Kin Name',
        'Next of Kin Phone',
        'Next of Kin Relationship',
        'Created At',
        'Updated At'
    ];
    exportCsvWithHeaders(headers, rows, `fa-register-${todayKey()}.csv`);
    logAudit('Exported FA register', `Rows: ${rows.length}`);
    logExportHistory('FA Register Export', rows.length);
}

function buildClientRegistryKeyFromLead(lead) {
    const idRaw = String(lead?.clientIdRaw || '').trim().toLowerCase();
    if (idRaw) return `id:${idRaw}`;
    const name = normalizeLeadText(lead?.clientNameRaw || lead?.clientName || '');
    const cellDigits = String(lead?.clientCellRaw || lead?.clientCell || '').replace(/\D/g, '');
    if (!name) return '';
    return `name:${name}|cell:${cellDigits}`;
}

function renderMasterClientsRegistry() {
    const clients = leadRecords
        .map((lead) => ({
            key: buildClientRegistryKeyFromLead(lead),
            name: lead.clientNameRaw || lead.clientName || '',
            joinedAt: lead.timestamp || '',
            lid: lead.leadId || ''
        }))
        .filter((item) => item.name && item.key)
        .sort((a, b) => (b.joinedAt || '').localeCompare(a.joinedAt || ''));
    const uniqueMap = new Map();
    clients.forEach((client) => {
        if (!client.key) return;
        if (uniqueMap.has(client.key)) return;
        uniqueMap.set(client.key, client);
    });
    const uniqueClients = [...uniqueMap.values()];
    return `
        <div class="insight-card">
            <h4>Clients</h4>
            <p class="page-subtitle">Admin (All) can view and securely remove confidential client data.</p>
            <div class="insight-list">
                <span class="insight-chip">Unique Clients Captured: ${uniqueClients.length}</span>
                <span class="insight-chip">Full Client List: Enabled</span>
            </div>
            ${uniqueClients.length ? `
                <div class="learning-search" style="margin-top:10px;">
                    <input type="text" id="masterClientsSearchInput" placeholder="Search clients by name or LID..." oninput="filterMasterClientsRegistry(this.value)">
                </div>
                <div class="mini-table" style="margin-top:12px;">
                    <table>
                        <thead>
                            <tr>
                                <th>Client</th>
                                <th>Latest LID</th>
                                <th>Last Seen</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="masterClientsTbody">
                            ${uniqueClients.map((client) => `
                                <tr>
                                    <td>${escapeHtml(client.name)}</td>
                                    <td>${escapeHtml(client.lid || '—')}</td>
                                    <td>${client.joinedAt ? new Date(client.joinedAt).toLocaleString('en-ZA') : '—'}</td>
                                    <td>
                                        <button class="action-btn secondary" type="button" onclick="deleteClientInfoFromRegistry('${encodeURIComponent(client.key)}','${encodeURIComponent(client.name)}')">
                                            Delete Client Info
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle" style="margin-top:10px;">No client records captured yet.</p>'}
        </div>
    `;
}

function filterMasterClientsRegistry(query = '') {
    const tbody = document.getElementById('masterClientsTbody');
    if (!tbody) return;
    const term = String(query || '').trim().toLowerCase();
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.forEach((row) => {
        const hay = String(row.textContent || '').toLowerCase();
        row.style.display = !term || hay.includes(term) ? '' : 'none';
    });
}

function renderMasterTeamLeaderManager() {
    const leaders = getTeamLeaderAccounts();
    return `
        <div class="insight-card">
            <h4>Team Leader Management</h4>
            <p class="page-subtitle">Only Admin (All) can add, edit, or remove team leaders and their team portals.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="masterLeaderTeam">Team Name</label>
                    <input type="text" id="masterLeaderTeam" placeholder="e.g. Team New Horizon">
                </div>
                <div class="form-group">
                    <label for="masterLeaderName">Leader Username / Name</label>
                    <input type="text" id="masterLeaderName" placeholder="e.g. New Team Leader">
                </div>
                <div class="form-group">
                    <label for="masterLeaderEmail">Leader Email</label>
                    <input type="email" id="masterLeaderEmail" placeholder="leader@matla.co.za">
                </div>
                <div class="form-group">
                    <label for="masterLeaderPassword">Temporary Password</label>
                    <input type="password" id="masterLeaderPassword" placeholder="Strong password">
                    <div id="masterLeaderPasswordStrength" class="password-strength" aria-live="polite"></div>
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="createMasterTeamLeader()">Create Team Leader</button>
            </div>
            <div class="mini-table admin-team-leader-editor-table-wrap" style="margin-top:12px;">
                <table class="team-leader-editor-table mobile-stack-table">
                    <thead>
                        <tr>
                            <th>Leader</th>
                            <th>Team</th>
                            <th>Email</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${leaders.length ? leaders.map((leader) => {
                            const encoded = encodeURIComponent(leader.key);
                            return `
                            <tr>
                                <td data-label="Leader"><input type="text" id="mtl-name-${encoded}" value="${escapeHtml(leader.username)}"></td>
                                <td data-label="Team"><input type="text" id="mtl-team-${encoded}" value="${escapeHtml(leader.team || '')}"></td>
                                <td data-label="Email"><input type="email" id="mtl-email-${encoded}" value="${escapeHtml(leader.email || '')}"></td>
                                <td data-label="Actions">
                                    <div class="facility-inline-actions">
                                        <button class="action-btn secondary" type="button" onclick="saveMasterTeamLeader('${encoded}')">Save</button>
                                        <button class="action-btn secondary" type="button" onclick="removeMasterTeamLeader('${encoded}')">Remove</button>
                                    </div>
                                </td>
                            </tr>
                        `;
                        }).join('') : '<tr><td colspan="4" class="mobile-stack-empty-row">No team leaders configured yet.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

async function createMasterTeamLeader() {
    if (adminRole !== 'ADMIN') return;
    const teamEl = document.getElementById('masterLeaderTeam');
    const nameEl = document.getElementById('masterLeaderName');
    const emailEl = document.getElementById('masterLeaderEmail');
    const passEl = document.getElementById('masterLeaderPassword');
    if (!teamEl || !nameEl || !emailEl || !passEl) return;
    const team = String(teamEl.value || '').trim();
    const username = formatJfaName(nameEl.value || '');
    const email = String(emailEl.value || '').trim().toLowerCase();
    const password = String(passEl.value || '').trim();
    if (!team || !username || !email || !password) {
        showToast('Complete team leader details first.', 'error');
        return;
    }
    if (!isValidEmail(email)) {
        showToast('Enter a valid team leader email.', 'error');
        return;
    }
    const passwordValidation = validateStrongPassword(password);
    if (!passwordValidation.ok) {
        showToast(passwordValidation.message, 'error');
        return;
    }
    const accounts = getUserAccounts();
    const key = normalizeJfaName(username);
    if (isUsernameUnavailable(username, accounts)) {
        showToast('That username has been used before. Please choose a different one.', 'error');
        return;
    }
    const emailTaken = Object.values(accounts).some((account) => String(account?.email || '').toLowerCase() === email);
    if (emailTaken) {
        showToast('That email is already in use.', 'error');
        return;
    }
    const record = await createPasswordRecord(password);
    accounts[key] = {
        username,
        email,
        team,
        passwordHash: record.hash,
        passwordSalt: record.salt,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        active: true,
        permissions: normalizeUserPermissions({ admin: true, learning: true, forms: true, leads: true, settings: true }, false)
    };
    saveUserAccounts(accounts);
    markUsernameAsUsed(username);
    const profile = ensureJfaProfile(username, { team }) || {};
    profile.team = team;
    profile.email = email;
    jfaProfiles[key] = profile;
    saveJfaProfiles();
    logUserMgmtAction('Team leader created', `${username} • ${team}`);
    renderTeamPortalButtons();
    refreshTeamSelectOptions();
    renderAdminMasterLogger();
    showToast('Team leader created and team portal enabled.', 'success');
}

function saveMasterTeamLeader(keyRaw) {
    if (adminRole !== 'ADMIN') return;
    const encoded = String(keyRaw || '');
    const key = normalizeJfaName(decodeURIComponent(encoded));
    const nameEl = document.getElementById(`mtl-name-${encoded}`);
    const teamEl = document.getElementById(`mtl-team-${encoded}`);
    const emailEl = document.getElementById(`mtl-email-${encoded}`);
    const username = formatJfaName(nameEl?.value || '');
    const team = String(teamEl?.value || '').trim();
    const email = String(emailEl?.value || '').trim().toLowerCase();
    if (!username) {
        showToast('Leader name cannot be blank.', 'error');
        return;
    }
    if (!team) {
        showToast('Team cannot be blank.', 'error');
        return;
    }
    if (email && !isValidEmail(email)) {
        showToast('Enter a valid email address.', 'error');
        return;
    }
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        showToast('Team leader account not found.', 'error');
        return;
    }
    const nextKey = normalizeJfaName(username);
    if (!nextKey) {
        showToast('Invalid leader name.', 'error');
        return;
    }
    if (nextKey !== key && isUsernameUnavailable(username, accounts)) {
        showToast('That username has been used before. Please choose a different one.', 'error');
        return;
    }
    if (email) {
        const emailTaken = Object.entries(accounts).some(([entryKey, entry]) => {
            if (entryKey === key) return false;
            return String(entry?.email || '').toLowerCase() === email;
        });
        if (emailTaken) {
            showToast('That email is already in use by another account.', 'error');
            return;
        }
    }
    account.username = username;
    account.team = team;
    account.permissions = normalizeUserPermissions({ ...(account.permissions || {}), admin: true }, false);
    account.updatedAt = new Date().toISOString();
    if (email) account.email = email;
    if (nextKey !== key) {
        delete accounts[key];
        accounts[nextKey] = account;
    } else {
        accounts[key] = account;
    }
    saveUserAccounts(accounts);
    markUsernameAsUsed(username);
    const profile = ensureJfaProfile(account.username || nextKey, { team }) || {};
    profile.team = team;
    if (email) profile.email = email;
    if (nextKey !== key && jfaProfiles[key]) {
        delete jfaProfiles[key];
    }
    jfaProfiles[nextKey] = profile;
    saveJfaProfiles();
    logUserMgmtAction('Team leader updated', `${formatJfaName(account.username || nextKey)} • ${team}`);
    renderTeamPortalButtons();
    refreshTeamSelectOptions();
    renderAdminMasterLogger();
    showToast('Team leader updated.', 'success');
}

async function removeMasterTeamLeader(keyRaw) {
    if (adminRole !== 'ADMIN') return;
    const key = normalizeJfaName(decodeURIComponent(String(keyRaw || '')));
    const accounts = getUserAccounts();
    const account = accounts[key];
    if (!account) {
        showToast('Team leader account not found.', 'error');
        return;
    }
    const confirmed = await openAppConfirmModal({
        title: 'Remove Team Leader Access?',
        message: `Remove team-leader privileges for ${formatJfaName(account.username || key)}?`,
        confirmText: 'Remove',
        cancelText: 'Cancel'
    });
    if (!confirmed) return;
    account.permissions = normalizeUserPermissions({ ...(account.permissions || {}), admin: false }, false);
    account.team = '';
    account.updatedAt = new Date().toISOString();
    accounts[key] = account;
    saveUserAccounts(accounts);
    if (jfaProfiles[key]) {
        jfaProfiles[key].team = '';
        saveJfaProfiles();
    }
    logUserMgmtAction('Team leader removed', `${formatJfaName(account.username || key)}`);
    renderTeamPortalButtons();
    refreshTeamSelectOptions();
    renderAdminMasterLogger();
    showToast('Team leader access removed.', 'success');
}

function renderMasterSubmittedLeads() {
    const rows = getFilteredAdminLeads().sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    const availableFas = getFaRegisterDirectory().filter((fa) => fa.active);
    const pendingUnassignedLeads = leadRecords
        .filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Pending' && !String(lead.assignedFaUserKey || '').trim())
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    const resolveField = (lead, rawKey, maskedKey) => {
        const raw = lead?.[rawKey];
        if (raw != null && String(raw).trim()) return raw;
        return lead?.[maskedKey] || '—';
    };
    const teams = [...new Set(leadRecords.map((lead) => String(lead.jfaTeam || '').trim()).filter(Boolean))].sort();
    const jfas = [...new Set(leadRecords.map((lead) => formatJfaName(lead.jfaName || '')).filter(Boolean))].sort();
    const products = [...new Set(leadRecords.map((lead) => String(lead.product || '').trim()).filter(Boolean))].sort();
    return `
        <div class="insight-card">
            <h4>Submitted Leads</h4>
            <p class="page-subtitle">Confidential: full client details are visible only to Admin (All).</p>
            <div class="master-capture-grid" style="margin-bottom:10px;">
                <div class="form-group">
                    <label for="adminLeadFilterFrom">From Date</label>
                    <input type="date" id="adminLeadFilterFrom" value="${escapeHtml(adminLeadFilters.from)}" onchange="setAdminLeadFilter('from', this.value)">
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterTo">To Date</label>
                    <input type="date" id="adminLeadFilterTo" value="${escapeHtml(adminLeadFilters.to)}" onchange="setAdminLeadFilter('to', this.value)">
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterTeam">Team</label>
                    <select id="adminLeadFilterTeam" onchange="setAdminLeadFilter('team', this.value)">
                        <option value="">All Teams</option>
                        ${teams.map((team) => `<option value="${escapeHtml(team)}" ${adminLeadFilters.team === team ? 'selected' : ''}>${escapeHtml(team)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterJfa">JFA</label>
                    <select id="adminLeadFilterJfa" onchange="setAdminLeadFilter('jfa', this.value)">
                        <option value="">All JFAs</option>
                        ${jfas.map((name) => `<option value="${escapeHtml(name)}" ${adminLeadFilters.jfa === name ? 'selected' : ''}>${escapeHtml(name)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterProduct">Product</label>
                    <select id="adminLeadFilterProduct" onchange="setAdminLeadFilter('product', this.value)">
                        <option value="">All Products</option>
                        ${products.map((product) => `<option value="${escapeHtml(product)}" ${adminLeadFilters.product === product ? 'selected' : ''}>${escapeHtml(product)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterStatus">Status</label>
                    <select id="adminLeadFilterStatus" onchange="setAdminLeadFilter('status', this.value)">
                        <option value="">All Statuses</option>
                        ${LEAD_STATUS_OPTIONS.map((status) => `<option value="${escapeHtml(status)}" ${adminLeadFilters.status === status ? 'selected' : ''}>${escapeHtml(status)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="adminLeadFilterGeoStatus">Geo Status</label>
                    <select id="adminLeadFilterGeoStatus" onchange="setAdminLeadFilter('geoStatus', this.value)">
                        <option value="">All Geo Statuses</option>
                        ${['Captured', 'Captured (Cached)', 'Permission Denied', 'Timed Out', 'Error', 'Unavailable', 'Unknown']
                            .map((status) => `<option value="${escapeHtml(status)}" ${adminLeadFilters.geoStatus === status ? 'selected' : ''}>${escapeHtml(status)}</option>`)
                            .join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="radio-option">
                        <input type="checkbox" id="adminLeadFilterWill" ${adminLeadFilters.willOnly ? 'checked' : ''} onchange="toggleAdminLeadWill(this.checked)">
                        <span class="radio-label">Has Will Only</span>
                    </label>
                </div>
            </div>
            <div class="menu-page-actions" style="margin-bottom:10px;">
                <button class="action-btn secondary" type="button" onclick="exportAdminLeadsCsv()">Export Leads CSV</button>
                <button class="action-btn secondary" type="button" onclick="exportAdminLeadsPdf()">Export Leads PDF</button>
                <button class="action-btn secondary" type="button" onclick="clearAdminLeadFilters()">Clear Filters</button>
            </div>
            ${rows.length ? `
                <div class="mini-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>LID</th>
                                <th>JFA</th>
                                <th>Team</th>
                                <th>Geo Status</th>
                                <th>Coordinates / Map</th>
                                <th>Accuracy</th>
                                <th>Geo Captured</th>
                                <th>Product</th>
                                <th>Status</th>
                                <th>Payment</th>
                                <th>Assigned FA</th>
                                <th>Reason / Commission</th>
                                <th>Signed At</th>
                                <th>Client</th>
                                <th>Client ID</th>
                                <th>Contact</th>
                                <th>Address</th>
                                <th>Signature</th>
                                <th>Authorized User</th>
                                <th>Authorized ID</th>
                                <th>Email</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows.map((lead) => {
                                const statusValue = normalizeLeadStatus(lead.status);
                                const paymentValue = normalizePaymentStatus(lead.paymentStatus);
                                const encodedId = encodeURIComponent(lead.id || '');
                                const leadNumber = lead.leadId || '—';
                                const reasonValue = lead.failureReason || '';
                                const commissionValue = lead.commissionDate || '';
                                const hasSignature = Boolean(lead.clientSignatureImage);
                                const geo = getLeadGeoSummary(lead);
                                return `
                                <tr>
                                    <td>${lead.timestamp ? new Date(lead.timestamp).toLocaleString('en-ZA') : '—'}</td>
                                    <td>
                                        <div class="payment-meta" style="gap:6px;">
                                            <span>${escapeHtml(leadNumber)}</span>
                                            <button class="copy-btn" type="button" onclick="copyToClipboard('${escapeHtml(leadNumber)}','LID copied')">Copy</button>
                                        </div>
                                    </td>
                                    <td>${escapeHtml(formatJfaName(lead.jfaName || ''))}</td>
                                    <td>${escapeHtml(lead.jfaTeam || '—')}</td>
                                    <td>${escapeHtml(geo.statusLabel)}</td>
                                    <td>
                                        <div class="mini-input-stack">
                                            <span>${escapeHtml(geo.coordsText)}</span>
                                            ${geo.mapUrl ? `<a class="copy-btn" href="${escapeHtml(geo.mapUrl)}" target="_blank" rel="noopener">Open Map</a>` : '<span class="page-subtitle">—</span>'}
                                        </div>
                                    </td>
                                    <td>${escapeHtml(`${geo.accuracyText} • ${geo.quality}`)}</td>
                                    <td>${escapeHtml(geo.capturedText)}</td>
                                    <td>${escapeHtml(lead.product || '—')}</td>
                                    <td>
                                        <select onchange="updateLeadStatus('${encodedId}', this.value)">
                                            ${LEAD_STATUS_OPTIONS.map((status) => `<option value="${escapeHtml(status)}" ${statusValue === status ? 'selected' : ''}>${escapeHtml(status)}</option>`).join('')}
                                        </select>
                                    </td>
                                    <td>
                                        <select onchange="updateLeadPaymentStatus('${encodedId}', this.value)">
                                            ${PAYMENT_STATUS_OPTIONS.map((status) => `<option value="${escapeHtml(status)}" ${paymentValue === status ? 'selected' : ''}>${escapeHtml(status)}</option>`).join('')}
                                        </select>
                                    </td>
                                    <td>
                                        <div class="mini-input-stack">
                                            <span>${escapeHtml(formatJfaName(lead.assignedFaName || 'Unassigned'))}</span>
                                            <span class="page-subtitle">${lead.assignedFaAt ? new Date(lead.assignedFaAt).toLocaleString('en-ZA') : '—'}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="mini-input-stack">
                                            <input type="text" placeholder="Reason (if unsuccessful)" value="${escapeHtml(reasonValue)}" onblur="updateLeadFailureReason('${encodedId}', this.value)">
                                            <input type="date" value="${escapeHtml(commissionValue)}" onblur="updateLeadCommissionDate('${encodedId}', this.value)">
                                        </div>
                                    </td>
                                    <td>${escapeHtml(lead.signedAt || '—')}</td>
                                    <td>${escapeHtml(resolveField(lead, 'clientNameRaw', 'clientName'))}</td>
                                    <td>${escapeHtml(resolveField(lead, 'clientIdRaw', 'clientId'))}</td>
                                    <td>${escapeHtml(resolveField(lead, 'clientCellRaw', 'clientCell'))}</td>
                                    <td>${escapeHtml(resolveField(lead, 'clientAddressRaw', 'clientAddress'))}</td>
                                    <td>
                                        ${hasSignature
                                            ? `<button class="action-btn secondary" type="button" onclick="openLeadSignaturePreview('${encodedId}')">View</button>`
                                            : '<span class="page-subtitle">—</span>'}
                                    </td>
                                    <td>${escapeHtml(lead.authorizedUser || '—')}</td>
                                    <td>${escapeHtml(resolveField(lead, 'authorizedIdRaw', 'authorizedId'))}</td>
                                    <td>${escapeHtml(resolveField(lead, 'authorizedEmailRaw', 'authorizedEmail'))}</td>
                                </tr>
                            `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle">No leads submitted yet.</p>'}
            <div class="menu-page-actions" style="margin-top:12px;">
                <label for="allocateFaSelect"><strong>Allocate to FA</strong></label>
                <select id="allocateLeadSelect" ${pendingUnassignedLeads.length ? '' : 'disabled'}>
                    ${pendingUnassignedLeads.length
                        ? pendingUnassignedLeads.map((lead) => {
                            const label = `${lead.leadId || 'LID'} • ${resolveField(lead, 'clientNameRaw', 'clientName')} • ${formatJfaName(lead.jfaName || 'JFA')}`;
                            return `<option value="${escapeHtml(String(lead.id || ''))}">${escapeHtml(label)}</option>`;
                        }).join('')
                        : '<option value="">No pending unassigned leads</option>'}
                </select>
                <select id="allocateFaSelect" ${availableFas.length ? '' : 'disabled'}>
                    ${availableFas.length
                        ? availableFas.map((fa) => `<option value="${escapeHtml(fa.key)}">${escapeHtml(`${fa.name} • ${fa.team || 'No Team'}`)}</option>`).join('')
                        : '<option value="">No active FAs available</option>'}
                </select>
                <button class="action-btn secondary" type="button" ${availableFas.length && pendingUnassignedLeads.length ? '' : 'disabled'} onclick="allocateLeadToFaFromAdmin()">Allocate</button>
            </div>
        </div>
    `;
}

async function deleteClientInfoFromRegistry(encodedKey, encodedName) {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) {
        showToast('Only Admin (All) can delete client info.', 'error');
        return;
    }
    const clientKey = decodeURIComponent(String(encodedKey || '')).trim();
    const clientName = decodeURIComponent(String(encodedName || '')).trim();
    if (!clientKey) {
        showToast('Client key is missing.', 'error');
        return;
    }
    if (!clientName) {
        showToast('Client name is missing.', 'error');
        return;
    }
    const matchingLeads = leadRecords.filter((lead) => {
        return buildClientRegistryKeyFromLead(lead) === clientKey;
    });
    if (!matchingLeads.length) {
        showToast('No client records found for deletion.', 'error');
        return;
    }
    const ok = await openAppConfirmModal({
        title: 'Delete Client Info',
        message: `Delete confidential client info for ${clientName} from ${matchingLeads.length} lead record(s)?`,
        confirmText: 'Delete',
        cancelText: 'Cancel'
    });
    if (!ok) return;

    const affectedLeadIds = new Set(matchingLeads.map((lead) => String(lead?.leadId || '').trim()).filter(Boolean));
    matchingLeads.forEach((lead) => {
        lead.clientNameRaw = '';
        lead.clientName = '[Deleted]';
        lead.clientIdRaw = '';
        lead.clientId = '';
        lead.clientPersalRaw = '';
        lead.clientPersal = '';
        lead.clientAddressRaw = '';
        lead.clientAddress = '';
        lead.clientCellRaw = '';
        lead.clientCell = '';
        lead.clientHomeRaw = '';
        lead.clientHome = '';
        lead.clientEmailRaw = '';
        lead.clientEmail = '';
        lead.clientSignatureImage = '';
        lead.authorizedUser = '';
        lead.authorizedIdRaw = '';
        lead.authorizedId = '';
        lead.authorizedEmailRaw = '';
        lead.authorizedEmail = '';
    });
    appointmentRecords.forEach((appointment) => {
        const lid = String(appointment?.leadId || '').trim();
        if (!lid || !affectedLeadIds.has(lid)) return;
        appointment.clientName = '[Deleted]';
        appointment.clientPhone = '';
        appointment.updatedAt = new Date().toISOString();
    });

    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    saveAppointments();
    logAudit('Client info deleted', `${clientName} • Records affected: ${matchingLeads.length} • by ${getAuditActorLabel()}`);
    showToast(`Client info deleted for ${clientName}.`, 'success');
    renderAdminMasterLogger();
}

function allocateLeadToFaFromAdmin() {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) {
        showToast('Only Admin (All) can allocate leads to FAs.', 'error');
        return;
    }
    const leadSelect = document.getElementById('allocateLeadSelect');
    const faSelect = document.getElementById('allocateFaSelect');
    const leadId = String(leadSelect?.value || '').trim();
    const faKey = normalizeJfaName(faSelect?.value || '');
    if (!leadId) {
        showToast('Select a lead to allocate.', 'error');
        return;
    }
    if (!faKey) {
        showToast('Select an FA to allocate to.', 'error');
        return;
    }
    const lead = leadRecords.find((item) => String(item.id || '') === leadId);
    if (!lead) {
        showToast('Lead not found.', 'error');
        return;
    }
    const fas = getFaRegisterDirectory();
    const targetFa = fas.find((fa) => normalizeJfaName(fa.key) === faKey && fa.active);
    if (!targetFa) {
        showToast('Selected FA is not active or not found.', 'error');
        return;
    }
    lead.assignedFaUserKey = targetFa.key;
    lead.assignedFaName = targetFa.name;
    lead.assignedFaAt = new Date().toISOString();
    lead.routeReason = 'manual-admin';
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    logAudit(
        'Lead allocated to FA',
        `${lead.leadId || lead.id} • ${formatJfaName(lead.jfaName || '')} -> ${formatJfaName(targetFa.name || '')} • by ${getAuditActorLabel()}`
    );
    if (lead.jfaTeam) {
        pushSystemNotification(
            'TEAM',
            lead.jfaTeam,
            'Lead Allocation',
            `Lead ${lead.leadId || ''} was allocated to FA ${formatJfaName(targetFa.name || '')}.`
        );
    }
    showToast(`Allocated ${lead.leadId || 'lead'} to ${formatJfaName(targetFa.name || '')}.`, 'success');
    renderAdminMasterLogger();
}

function exportAdminLeadsCsv() {
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can export leads.', 'error');
        return;
    }
    const filtered = getFilteredAdminLeads();
    if (!filtered.length) {
        showToast('No leads found to export.', 'error');
        return;
    }
    const headers = [
        'Timestamp',
        'Lead ID',
        'JFA',
        'Team',
        'Product',
        'Status',
        'Payment Status',
        'Failure Reason',
        'Commission Date',
        'Signed At',
        'Signed Date',
        'Client Name',
        'Client ID',
        'Persal',
        'Address',
        'Cell',
        'Home',
        'Email',
        'Authorized User',
        'Authorized ID',
        'Authorized Email',
        'Intermediary',
        'Wants Will',
        'Notes',
        'Geo Status',
        'Geo Latitude',
        'Geo Longitude',
        'Geo Accuracy (m)',
        'Geo Quality',
        'Geo Captured At',
        'Geo Map URL'
    ];
    const rows = filtered.map((lead) => {
        const resolve = (rawKey, maskedKey) => {
            const raw = lead?.[rawKey];
            if (raw != null && String(raw).trim()) return raw;
            return lead?.[maskedKey] || '';
        };
        const geo = getLeadGeoSummary(lead);
        return [
            lead.timestamp || '',
            lead.leadId || '',
            formatJfaName(lead.jfaName || ''),
            lead.jfaTeam || '',
            lead.product || '',
            normalizeLeadStatus(lead.status),
            normalizePaymentStatus(lead.paymentStatus),
            lead.failureReason || '',
            lead.commissionDate || '',
            lead.signedAt || '',
            lead.signedDate || '',
            resolve('clientNameRaw', 'clientName'),
            resolve('clientIdRaw', 'clientId'),
            resolve('clientPersalRaw', 'clientPersal'),
            resolve('clientAddressRaw', 'clientAddress'),
            resolve('clientCellRaw', 'clientCell'),
            resolve('clientHomeRaw', 'clientHome'),
            resolve('clientEmailRaw', 'clientEmail'),
            lead.authorizedUser || '',
            resolve('authorizedIdRaw', 'authorizedId'),
            resolve('authorizedEmailRaw', 'authorizedEmail'),
            lead.intermediary || '',
            lead.wantsWill ? 'YES' : 'NO',
            lead.notes || '',
            geo.statusLabel,
            geo.lat ?? '',
            geo.lng ?? '',
            geo.accuracy ?? '',
            geo.quality,
            geo.capturedRaw || '',
            geo.mapUrl || ''
        ];
    });
    exportCsvWithHeaders(headers, rows, `admin-leads-${todayKey()}.csv`, 'Admin Leads Export');
    logAudit('Exported leads', `Rows: ${rows.length}`);
    logExportHistory('Leads Export', rows.length);
}

function exportAdminLeadsPdf() {
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can export leads.', 'error');
        return;
    }
    const filtered = getFilteredAdminLeads();
    if (!filtered.length) {
        showToast('No leads found to export.', 'error');
        return;
    }
    const headers = [
        'Timestamp',
        'Lead ID',
        'JFA',
        'Team',
        'Product',
        'Status',
        'Payment Status',
        'Failure Reason',
        'Commission Date',
        'Signed At',
        'Signed Date',
        'Client Name',
        'Client ID',
        'Persal',
        'Address',
        'Cell',
        'Home',
        'Email',
        'Authorized User',
        'Authorized ID',
        'Authorized Email',
        'Intermediary',
        'Wants Will',
        'Notes',
        'Geo Status',
        'Geo Latitude',
        'Geo Longitude',
        'Geo Accuracy (m)',
        'Geo Quality',
        'Geo Captured At',
        'Geo Map URL'
    ];
    const rows = filtered.map((lead) => {
        const resolve = (rawKey, maskedKey) => {
            const raw = lead?.[rawKey];
            if (raw != null && String(raw).trim()) return raw;
            return lead?.[maskedKey] || '';
        };
        const geo = getLeadGeoSummary(lead);
        return [
            lead.timestamp || '',
            lead.leadId || '',
            formatJfaName(lead.jfaName || ''),
            lead.jfaTeam || '',
            lead.product || '',
            normalizeLeadStatus(lead.status),
            normalizePaymentStatus(lead.paymentStatus),
            lead.failureReason || '',
            lead.commissionDate || '',
            lead.signedAt || '',
            lead.signedDate || '',
            resolve('clientNameRaw', 'clientName'),
            resolve('clientIdRaw', 'clientId'),
            resolve('clientPersalRaw', 'clientPersal'),
            resolve('clientAddressRaw', 'clientAddress'),
            resolve('clientCellRaw', 'clientCell'),
            resolve('clientHomeRaw', 'clientHome'),
            resolve('clientEmailRaw', 'clientEmail'),
            lead.authorizedUser || '',
            resolve('authorizedIdRaw', 'authorizedId'),
            resolve('authorizedEmailRaw', 'authorizedEmail'),
            lead.intermediary || '',
            lead.wantsWill ? 'YES' : 'NO',
            lead.notes || '',
            geo.statusLabel,
            geo.lat ?? '',
            geo.lng ?? '',
            geo.accuracy ?? '',
            geo.quality,
            geo.capturedRaw || '',
            geo.mapUrl || ''
        ];
    });
    exportPdfWithHeaders(headers, rows, `admin-leads-${todayKey()}.pdf`, 'Admin Leads Export');
    logAudit('Exported leads PDF', `Rows: ${rows.length}`);
    logExportHistory('Leads PDF Export', rows.length);
}

function setAdminLeadFilter(key, value) {
    if (!adminLeadFilters) return;
    adminLeadFilters[key] = value == null ? '' : String(value);
    renderAdminMasterLogger();
}

function toggleAdminLeadWill(checked) {
    if (!adminLeadFilters) return;
    adminLeadFilters.willOnly = Boolean(checked);
    renderAdminMasterLogger();
}

function updateLeadStatus(encodedId, nextStatus) {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) {
        showToast('Only Admin (All) can update lead status.', 'error');
        return;
    }
    const id = decodeURIComponent(encodedId || '');
    const lead = leadRecords.find((item) => String(item.id) === id);
    if (!lead) {
        showToast('Lead not found.', 'error');
        return;
    }
    const normalized = normalizeLeadStatus(nextStatus);
    const previousStatus = normalizeLeadStatus(lead.status);
    const previousPayment = normalizePaymentStatus(lead.paymentStatus);
    lead.status = normalized;
    if (normalized === 'Closed') {
        lead.paymentStatus = normalizePaymentStatus('Successful');
    } else if (normalized === 'Lost') {
        lead.paymentStatus = normalizePaymentStatus('Unsuccessful');
    } else {
        lead.paymentStatus = normalizePaymentStatus('Pending');
    }
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    const updatedPayment = normalizePaymentStatus(lead.paymentStatus);
    logAudit(
        'Lead status updated',
        `${lead.leadId || lead.id} • ${formatJfaName(lead.jfaName || '')} • status ${previousStatus} -> ${normalized} • payment ${previousPayment} -> ${updatedPayment} • by ${getAuditActorLabel()}`
    );
    showToast(`Lead status set to ${normalized}.`, 'success');
    if (updatedPayment !== previousPayment) {
        notifyPaymentStatusChange(lead, previousPayment, updatedPayment);
    }
}

function updateLeadPaymentStatus(encodedId, nextStatus) {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) {
        showToast('Only Admin (All) can update payment status.', 'error');
        return;
    }
    const id = decodeURIComponent(encodedId || '');
    const lead = leadRecords.find((item) => String(item.id) === id);
    if (!lead) {
        showToast('Lead not found.', 'error');
        return;
    }
    const normalized = normalizePaymentStatus(nextStatus);
    const previous = normalizePaymentStatus(lead.paymentStatus);
    lead.paymentStatus = normalized;
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    logAudit(
        'Lead payment updated',
        `${lead.leadId || lead.id} • ${formatJfaName(lead.jfaName || '')} • payment ${previous} -> ${normalized} • by ${getAuditActorLabel()}`
    );
    showToast(`Payment status set to ${normalized}.`, 'success');
    if (previous !== normalized) {
        notifyPaymentStatusChange(lead, previous, normalized);
    }
}

function updateLeadFailureReason(encodedId, value) {
    if (adminRole !== 'ADMIN') return;
    const id = decodeURIComponent(encodedId || '');
    const lead = leadRecords.find((item) => String(item.id) === id);
    if (!lead) return;
    const nextReason = String(value || '').trim();
    const previousReason = String(lead.failureReason || '').trim();
    lead.failureReason = nextReason;
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    if (nextReason !== previousReason) {
        logAudit(
            'Lead failure reason updated',
            `${lead.leadId || lead.id} • ${previousReason || '—'} -> ${nextReason || '—'} • by ${getAuditActorLabel()}`
        );
    }
}

function updateLeadCommissionDate(encodedId, value) {
    if (adminRole !== 'ADMIN') return;
    const id = decodeURIComponent(encodedId || '');
    const lead = leadRecords.find((item) => String(item.id) === id);
    if (!lead) return;
    const nextDate = String(value || '').trim();
    const previousDate = String(lead.commissionDate || '').trim();
    lead.commissionDate = nextDate;
    scheduleStorageWrite(STORAGE_KEYS.leads, JSON.stringify(leadRecords));
    if (nextDate !== previousDate) {
        logAudit(
            'Lead commission date updated',
            `${lead.leadId || lead.id} • ${previousDate || '—'} -> ${nextDate || '—'} • by ${getAuditActorLabel()}`
        );
    }
}

function notifyPaymentStatusChange(lead, previousStatus, nextStatus) {
    if (!lead) return;
    const team = lead.jfaTeam || '';
    const lid = lead.leadId || 'LID';
    const name = formatJfaName(lead.jfaName || 'JFA');
    const statusLine = `${previousStatus} → ${nextStatus}`;
    let message = `Payment status updated for ${name} (${lid}): ${statusLine}.`;
    if (nextStatus === 'Unsuccessful' && lead.failureReason) {
        message += ` Reason: ${lead.failureReason}.`;
    }
    if (nextStatus === 'Successful' && lead.commissionDate) {
        message += ` Commission date: ${lead.commissionDate}.`;
    }
    if (team) {
        pushSystemNotification('TEAM', team, 'Payment Update', message);
    } else {
        pushSystemNotification('ALL', '', 'Payment Update', message);
    }
}

function getFilteredAdminLeads() {
    if (adminRole !== 'ADMIN') return [];
    const fromInput = document.getElementById('adminLeadFilterFrom');
    const toInput = document.getElementById('adminLeadFilterTo');
    const teamInput = document.getElementById('adminLeadFilterTeam');
    const jfaInput = document.getElementById('adminLeadFilterJfa');
    const productInput = document.getElementById('adminLeadFilterProduct');
    const statusInput = document.getElementById('adminLeadFilterStatus');
    const geoInput = document.getElementById('adminLeadFilterGeoStatus');
    const willInput = document.getElementById('adminLeadFilterWill');
    const fromValue = fromInput?.value || adminLeadFilters.from;
    const toValue = toInput?.value || adminLeadFilters.to;
    const fromDate = fromValue ? new Date(`${fromValue}T00:00:00`) : null;
    const toDate = toValue ? new Date(`${toValue}T23:59:59`) : null;
    const team = (teamInput?.value || adminLeadFilters.team || '').trim().toLowerCase();
    const jfa = (jfaInput?.value || adminLeadFilters.jfa || '').trim().toLowerCase();
    const product = (productInput?.value || adminLeadFilters.product || '').trim().toLowerCase();
    const status = (statusInput?.value || adminLeadFilters.status || '').trim();
    const geoStatus = (geoInput?.value || adminLeadFilters.geoStatus || '').trim();
    const willOnly = Boolean(willInput?.checked ?? adminLeadFilters.willOnly);

    return leadRecords.filter((lead) => {
        if (fromDate || toDate) {
            const ts = lead.timestamp ? new Date(lead.timestamp) : null;
            if (!ts || (fromDate && ts < fromDate) || (toDate && ts > toDate)) return false;
        }
        if (team && String(lead.jfaTeam || '').toLowerCase() !== team) return false;
        if (jfa && formatJfaName(lead.jfaName || '').toLowerCase() !== jfa) return false;
        if (product && String(lead.product || '').toLowerCase() !== product) return false;
        if (status && normalizeLeadStatus(lead.status) !== status) return false;
        if (geoStatus && getGeoStatusLabel(lead?.geo?.status || 'unknown') !== geoStatus) return false;
        if (willOnly && !lead.wantsWill) return false;
        return true;
    });
}

function clearAdminLeadFilters() {
    adminLeadFilters = {
        from: '',
        to: '',
        team: '',
        jfa: '',
        product: '',
        status: '',
        geoStatus: '',
        willOnly: false
    };
    const ids = [
        'adminLeadFilterFrom',
        'adminLeadFilterTo',
        'adminLeadFilterTeam',
        'adminLeadFilterJfa',
        'adminLeadFilterProduct',
        'adminLeadFilterStatus',
        'adminLeadFilterGeoStatus',
        'adminLeadFilterWill'
    ];
    ids.forEach((id) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (el.type === 'checkbox') {
            el.checked = false;
        } else {
            el.value = '';
        }
    });
    renderAdminMasterLogger();
}

let paymentsTab = 'pending';
let paymentsSearchTerm = '';
let benSystemSearchTerm = '';

function setPaymentsTab(tab = 'pending') {
    const normalized = String(tab || 'pending').toLowerCase();
    paymentsTab = ['pending', 'unsuccessful', 'successful'].includes(normalized) ? normalized : 'pending';
    renderPaymentsPage();
}

function clearPaymentsSearch() {
    paymentsSearchTerm = '';
    const input = document.getElementById('paymentsSearchInput');
    if (input) input.value = '';
    renderPaymentsPage();
}

function saveAppointments() {
    scheduleStorageWrite(STORAGE_KEYS.appointments, JSON.stringify(appointmentRecords));
}

function getAppointmentReminderStateKey(userKey) {
    return `appointmentReminderState:${normalizeJfaName(userKey || '')}`;
}

function getAppointmentReminderState(userKey) {
    const key = getAppointmentReminderStateKey(userKey);
    try {
        const raw = JSON.parse(localStorage.getItem(key) || '{}');
        return raw && typeof raw === 'object' ? raw : {};
    } catch (_) {
        return {};
    }
}

function saveAppointmentReminderState(userKey, state) {
    const key = getAppointmentReminderStateKey(userKey);
    localStorage.setItem(key, JSON.stringify(state || {}));
}

function getUserAppointments(userName = appUser) {
    const key = normalizeJfaName(userName || '');
    if (!key) return [];
    return appointmentRecords.filter((item) => normalizeJfaName(item.jfaName) === key);
}

function getAppointmentDateTime(item) {
    const date = String(item?.date || '').trim();
    const time = String(item?.time || '').trim();
    if (!date || !time) return null;
    const dt = new Date(`${date}T${time}:00`);
    if (Number.isNaN(dt.getTime())) return null;
    return dt;
}

function getAppointmentDateTimeFromParts(date, time) {
    const safeDate = String(date || '').trim();
    const safeTime = String(time || '').trim();
    if (!safeDate || !safeTime) return null;
    const dt = new Date(`${safeDate}T${safeTime}:00`);
    if (Number.isNaN(dt.getTime())) return null;
    return dt;
}

function findAppointmentTimeConflict(payload, excludeLeadId = '') {
    const targetJfa = normalizeJfaName(payload?.jfaName || '');
    const targetLeadId = String(payload?.leadId || '').trim();
    const targetDateTime = getAppointmentDateTimeFromParts(payload?.date, payload?.time);
    if (!targetJfa || !targetDateTime) return null;
    const limitMinutes = 30;
    return appointmentRecords.find((item) => {
        if (!item) return false;
        if (String(item.leadId || '').trim() === String(excludeLeadId || '').trim()) return false;
        if (normalizeJfaName(item.jfaName || '') !== targetJfa) return false;
        const itemDateTime = getAppointmentDateTime(item);
        if (!itemDateTime) return false;
        const diff = Math.abs(itemDateTime.getTime() - targetDateTime.getTime()) / 60000;
        return diff < limitMinutes;
    }) || null;
}

function dispatchMorningAppointmentReminder() {
    const key = normalizeJfaName(appUser || '');
    if (!key) return;
    const now = new Date();
    const today = todayKey();
    const state = getAppointmentReminderState(key);
    if (state.morningDay === today) return;
    const todays = getUserAppointments(appUser)
        .filter((item) => String(item.date || '') === today)
        .map((item) => ({ ...item, dt: getAppointmentDateTime(item) }))
        .filter((item) => item.dt)
        .sort((a, b) => a.dt - b.dt);
    if (!todays.length) return;
    const next = todays.find((item) => item.dt >= now) || todays[0];
    const msg = todays.length === 1
        ? `You have 1 client appointment today at ${next.time}. LID: ${next.leadId || '—'}.`
        : `You have ${todays.length} client appointments today. Next at ${next.time}.`;
    pushSystemNotification('USER', '', 'Morning Appointment Reminder', msg, { userKey: key });
    state.morningDay = today;
    saveAppointmentReminderState(key, state);
}

function dispatchOneHourAppointmentReminders() {
    const key = normalizeJfaName(appUser || '');
    if (!key) return;
    const now = new Date();
    const state = getAppointmentReminderState(key);
    if (!state.hourSent || typeof state.hourSent !== 'object') state.hourSent = {};
    let changed = false;
    getUserAppointments(appUser).forEach((item) => {
        const dt = getAppointmentDateTime(item);
        if (!dt) return;
        const token = `${item.id || item.leadId || ''}:${item.date || ''}:${item.time || ''}`;
        if (!token) return;
        const diffMinutes = (dt.getTime() - now.getTime()) / 60000;
        if (diffMinutes <= 60 && diffMinutes > 0 && !state.hourSent[token]) {
            const message = `Client appointment in about 1 hour at ${item.time}. LID: ${item.leadId || '—'} (${item.clientName || 'Client'}).`;
            pushSystemNotification('USER', '', '1-Hour Appointment Reminder', message, { userKey: key });
            state.hourSent[token] = new Date().toISOString();
            changed = true;
        }
    });
    if (changed) {
        saveAppointmentReminderState(key, state);
    }
}

function startAppointmentReminderWatcher() {
    if (appointmentReminderWatcher) clearInterval(appointmentReminderWatcher);
    appointmentReminderWatcher = setInterval(() => {
        if (!appUser) return;
        dispatchOneHourAppointmentReminders();
        if (isPageActive('assignment-page')) {
            renderAssignmentAppointmentReminders();
        }
        refreshNotificationBadge();
    }, 60000);
}

function hydrateAppointmentsFromLeads() {
    let changed = false;
    leadRecords.forEach((lead) => {
        if (!lead?.leadId || !lead?.appointmentDate || !lead?.appointmentTime) return;
        const exists = appointmentRecords.some((item) => item.leadId === lead.leadId);
        if (exists) return;
        appointmentRecords.push({
            id: `apt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            leadId: lead.leadId,
            clientName: lead.clientNameRaw || lead.clientName || '',
            clientPhone: lead.clientCellRaw || lead.clientCell || '',
            jfaName: lead.jfaName || '',
            jfaTeam: lead.jfaTeam || '',
            date: lead.appointmentDate,
            time: lead.appointmentTime,
            status: 'Scheduled',
            createdAt: lead.timestamp || new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });
        changed = true;
    });
    if (changed) saveAppointments();
}

function getScopedLeadRecordsForAppointments() {
    if (adminRole === 'ADMIN') return [...leadRecords];
    if (adminRole === 'TEAM' && adminTeam) {
        return leadRecords.filter((lead) => String(lead.jfaTeam || '') === adminTeam);
    }
    const identity = getLeadIdentity();
    if (!identity?.name) return [];
    const key = normalizeJfaName(identity.name);
    return leadRecords.filter((lead) => normalizeJfaName(lead.jfaName) === key);
}

function getScopedAppointments() {
    if (adminRole === 'ADMIN') return [...appointmentRecords];
    if (adminRole === 'TEAM' && adminTeam) {
        return appointmentRecords.filter((item) => String(item.jfaTeam || '') === adminTeam);
    }
    const identity = getLeadIdentity();
    if (!identity?.name) return [];
    const key = normalizeJfaName(identity.name);
    return appointmentRecords.filter((item) => normalizeJfaName(item.jfaName) === key);
}

function upsertAppointment(payload) {
    if (!payload || !payload.leadId) {
        return { ok: false, message: 'Lead ID is required.' };
    }
    const dt = getAppointmentDateTimeFromParts(payload.date, payload.time);
    if (!dt) {
        return { ok: false, message: 'Invalid appointment date or time.' };
    }
    if (dt.getTime() < (Date.now() - 60 * 1000)) {
        return { ok: false, message: 'Appointment cannot be set in the past.' };
    }
    const existing = appointmentRecords.find((item) => item.leadId === payload.leadId);
    const conflict = findAppointmentTimeConflict(payload, existing?.leadId || '');
    if (conflict) {
        return {
            ok: false,
            message: `Scheduling conflict: ${formatJfaName(payload.jfaName || '')} already has an appointment near ${conflict.time} (${conflict.leadId || 'LID'}).`
        };
    }
    if (existing) {
        const noChanges =
            String(existing.date || '') === String(payload.date || '') &&
            String(existing.time || '') === String(payload.time || '') &&
            String(existing.clientName || '') === String(payload.clientName || '') &&
            String(existing.clientPhone || '') === String(payload.clientPhone || '') &&
            String(existing.jfaName || '') === String(payload.jfaName || '') &&
            String(existing.jfaTeam || '') === String(payload.jfaTeam || '');
        if (noChanges) {
            return { ok: true, unchanged: true };
        }
        existing.clientName = payload.clientName || existing.clientName || '';
        existing.clientPhone = payload.clientPhone || existing.clientPhone || '';
        existing.jfaName = payload.jfaName || existing.jfaName || '';
        existing.jfaTeam = payload.jfaTeam || existing.jfaTeam || '';
        existing.date = payload.date || existing.date || '';
        existing.time = payload.time || existing.time || '';
        existing.updatedAt = new Date().toISOString();
    } else {
        appointmentRecords.push({
            id: `apt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            leadId: payload.leadId,
            clientName: payload.clientName || '',
            clientPhone: payload.clientPhone || '',
            jfaName: payload.jfaName || '',
            jfaTeam: payload.jfaTeam || '',
            date: payload.date || '',
            time: payload.time || '',
            status: 'Scheduled',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });
    }
    saveAppointments();
    return { ok: true, unchanged: false };
}

function scheduleAppointmentFromLead(lead, date, time) {
    if (!lead || !lead.leadId || !date || !time) return { ok: false, message: 'Missing appointment details.' };
    return upsertAppointment({
        leadId: lead.leadId,
        clientName: lead.clientNameRaw || lead.clientName || '',
        clientPhone: lead.clientCellRaw || lead.clientCell || '',
        jfaName: lead.jfaName || '',
        jfaTeam: lead.jfaTeam || '',
        date,
        time
    });
}

function populateAppointmentFromLead(leadId) {
    const leads = getScopedLeadRecordsForAppointments();
    const lead = leads.find((item) => String(item.leadId || '') === String(leadId || ''));
    const nameEl = document.getElementById('appointmentClientName');
    const phoneEl = document.getElementById('appointmentClientPhone');
    const lidEl = document.getElementById('appointmentLid');
    if (!lead) {
        if (nameEl) nameEl.value = '';
        if (phoneEl) phoneEl.value = '';
        if (lidEl) lidEl.value = '';
        return;
    }
    if (nameEl) nameEl.value = lead.clientNameRaw || lead.clientName || '';
    if (phoneEl) phoneEl.value = lead.clientCellRaw || lead.clientCell || '';
    if (lidEl) lidEl.value = lead.leadId || '';
}

function saveAppointmentFromMenu() {
    const leadSelect = document.getElementById('appointmentLeadSelect');
    const dateEl = document.getElementById('appointmentDate');
    const timeEl = document.getElementById('appointmentTime');
    const leadId = String(leadSelect?.value || '').trim();
    const date = String(dateEl?.value || '').trim();
    const time = String(timeEl?.value || '').trim();
    if (!leadId) {
        showToast('Select a lead (LID).', 'error');
        return;
    }
    if (!date || !time) {
        showToast('Set appointment date and time.', 'error');
        return;
    }
    const leads = getScopedLeadRecordsForAppointments();
    const lead = leads.find((item) => String(item.leadId || '') === leadId);
    if (!lead) {
        showToast('Lead not found for your scope.', 'error');
        return;
    }
    const result = scheduleAppointmentFromLead(lead, date, time);
    if (!result?.ok) {
        showToast(result?.message || 'Could not save appointment.', 'error');
        return;
    }
    logAudit('Appointment set', `${lead.leadId} • ${formatJfaName(lead.jfaName || '')} • ${date} ${time}`);
    renderAppointmentsPage();
    renderAssignmentAppointmentReminders();
    dispatchOneHourAppointmentReminders();
    refreshNotificationBadge();
    showToast(result?.unchanged ? 'Appointment already up to date.' : 'Appointment saved.', 'success');
}

function deleteAppointment(id) {
    const before = appointmentRecords.length;
    appointmentRecords = appointmentRecords.filter((item) => String(item.id) !== String(id));
    if (appointmentRecords.length === before) return;
    saveAppointments();
    renderAppointmentsPage();
    renderAssignmentAppointmentReminders();
    showToast('Appointment removed.', 'success');
}

function renderAppointmentsPage() {
    const body = document.getElementById('appointmentsBody');
    const chip = document.getElementById('appointmentsScopeChip');
    if (!body) return;
    const leads = getScopedLeadRecordsForAppointments().sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    const appointments = getScopedAppointments().sort((a, b) => `${b.date || ''} ${b.time || ''}`.localeCompare(`${a.date || ''} ${a.time || ''}`));
    const now = new Date();
    const upcomingCount = appointments.filter((item) => {
        const dt = getAppointmentDateTime(item);
        return dt && dt >= now;
    }).length;
    const todayCount = appointments.filter((item) => String(item.date || '') === todayKey()).length;
    if (chip) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
        chip.textContent = `${label || 'Personal'} • Quotation Scheduling`;
    }
    const leadOptions = leads.length
        ? leads.map((lead) => {
            const lid = lead.leadId || '';
            const who = lead.clientNameRaw || lead.clientName || 'Client';
            return `<option value="${escapeHtml(lid)}">${escapeHtml(`${lid} • ${who}`)}</option>`;
        }).join('')
        : '<option value="">No leads available</option>';
    const rows = appointments.length
        ? appointments.map((item) => `
            <tr>
                <td>${escapeHtml(item.clientName || '—')}</td>
                <td>${escapeHtml(item.clientPhone || '—')}</td>
                <td>${escapeHtml(item.leadId || '—')}</td>
                <td>${escapeHtml(item.date || '—')}</td>
                <td>${escapeHtml(item.time || '—')}</td>
                <td>${escapeHtml(formatJfaName(item.jfaName || ''))}</td>
                <td>${escapeHtml(item.jfaTeam || '—')}</td>
                <td><button class="action-btn secondary" type="button" onclick="deleteAppointment('${escapeHtml(item.id)}')">Remove</button></td>
            </tr>
        `).join('')
        : '<tr><td colspan="8">No appointments captured yet.</td></tr>';
    body.innerHTML = `
        <div class="insight-card">
            <h4>Set Appointment</h4>
            <p class="page-subtitle">Use lead-linked LID to schedule client quotation date/time.</p>
            <div class="insight-list" style="margin-bottom:10px;">
                <span class="insight-chip">Total: ${appointments.length}</span>
                <span class="insight-chip">Today: ${todayCount}</span>
                <span class="insight-chip">Upcoming: ${upcomingCount}</span>
            </div>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="appointmentLeadSelect">Lead (LID)</label>
                    <select id="appointmentLeadSelect" onchange="populateAppointmentFromLead(this.value)">
                        <option value="">Select lead</option>
                        ${leadOptions}
                    </select>
                </div>
                <div class="form-group">
                    <label for="appointmentClientName">Client Name</label>
                    <input type="text" id="appointmentClientName" readonly>
                </div>
                <div class="form-group">
                    <label for="appointmentClientPhone">Client Phone</label>
                    <input type="text" id="appointmentClientPhone" readonly>
                </div>
                <div class="form-group">
                    <label for="appointmentLid">LID</label>
                    <input type="text" id="appointmentLid" readonly>
                </div>
                <div class="form-group">
                    <label for="appointmentDate">Date</label>
                    <input type="date" id="appointmentDate">
                </div>
                <div class="form-group">
                    <label for="appointmentTime">Time</label>
                    <input type="time" id="appointmentTime">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveAppointmentFromMenu()">Save Appointment</button>
            </div>
        </div>
        <div class="insight-card">
            <h4>Appointment Register</h4>
            <div class="mini-table">
                <table>
                    <thead>
                        <tr>
                            <th>Client Name</th>
                            <th>Phone</th>
                            <th>LID</th>
                            <th>Date</th>
                            <th>Time</th>
                            <th>JFA</th>
                            <th>Team</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        </div>
    `;
}

function getPaymentsScopedLeads() {
    if (adminRole === 'ADMIN') return leadRecords;
    if (adminRole === 'TEAM' && adminTeam) {
        return leadRecords
            .filter((lead) => String(lead.jfaTeam || '') === adminTeam)
            .map((lead) => sanitizeLeadForNonAdmin(lead));
    }
    const identity = getLeadIdentity();
    if (!identity?.name) return [];
    return leadRecords
        .filter((lead) => normalizeJfaName(lead.jfaName) === normalizeJfaName(identity.name))
        .map((lead) => sanitizeLeadForNonAdmin(lead));
}

function getBenSystemScopedAssignments() {
    const today = todayKey();
    const base = jfaRecords.filter((record) => {
        if (recordDateKey(record) !== today) return false;
        if (!record?.facility?.name) return false;
        if (!record?.name || isJfaArchived(record.name)) return false;
        if (isTeamLeaderName(record.name, record.team || '')) return false;
        if (adminRole === 'TEAM' && adminTeam) return String(record.team || '') === adminTeam;
        return true;
    });
    if (adminRole !== 'PERSONAL') return base;

    const identity = getLeadIdentity();
    if (!identity?.team) return base;
    return base.filter((record) => String(record.team || '') === String(identity.team || ''));
}

function getBenSystemGroupedData() {
    const records = getBenSystemScopedAssignments();
    const seenJfaKeys = new Set();
    const deduped = records
        .sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
        .filter((record) => {
            const key = `${normalizeJfaName(record.name)}|${record.team || ''}`;
            if (!key || seenJfaKeys.has(key)) return false;
            seenJfaKeys.add(key);
            return true;
        });
    const groups = new Map();
    deduped.forEach((record) => {
        const facilityName = String(record.facility?.name || '').trim();
        if (!facilityName) return;
        const facilityArea = String(record.facility?.area || '').trim();
        const facilityType = String(record.facility?.type || '').trim();
        const groupKey = `${normalizeFacilityName(facilityName)}|${normalizeFacilityName(facilityArea)}`;
        if (!groups.has(groupKey)) {
            groups.set(groupKey, {
                facilityName,
                facilityArea,
                facilityType,
                jfas: []
            });
        }
        groups.get(groupKey).jfas.push({
            name: formatJfaName(record.name || ''),
            team: record.team || 'Unassigned'
        });
    });
    return [...groups.values()].sort((a, b) => {
        const byLoad = b.jfas.length - a.jfas.length;
        if (byLoad !== 0) return byLoad;
        return a.facilityName.localeCompare(b.facilityName, 'en', { sensitivity: 'base' });
    });
}

function setBenSystemSearch(value = '') {
    benSystemSearchTerm = String(value || '').trim();
    renderBenSystemPage();
}

function clearBenSystemSearch() {
    benSystemSearchTerm = '';
    const input = document.getElementById('benSystemSearchInput');
    if (input) input.value = '';
    renderBenSystemPage();
}

function exportBenSystemCsv() {
    const grouped = getBenSystemGroupedData();
    const filtered = grouped.filter((group) => {
        if (!benSystemSearchTerm) return true;
        const term = benSystemSearchTerm.toLowerCase();
        const facilityHay = `${group.facilityName} ${group.facilityArea} ${group.facilityType}`.toLowerCase();
        const jfaHay = group.jfas.map((jfa) => `${jfa.name} ${jfa.team}`.toLowerCase()).join(' ');
        return facilityHay.includes(term) || jfaHay.includes(term);
    });
    const headers = ['Facility', 'Area', 'Type', 'JFA Name', 'Team'];
    const rows = [];
    filtered.forEach((group) => {
        group.jfas
            .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }))
            .forEach((jfa) => {
                rows.push([group.facilityName, group.facilityArea || '—', group.facilityType || 'Facility', jfa.name, jfa.team || '—']);
            });
    });
    const ok = exportCsvWithHeaders(headers, rows, `ben-system-${todayKey()}.csv`, 'Ben System Export');
    if (ok) {
        openBenExportModal(`CSV export is ready. ${rows.length} row(s) were included.`);
    }
}

function exportBenSystemPdf() {
    const grouped = getBenSystemGroupedData();
    const filtered = grouped.filter((group) => {
        if (!benSystemSearchTerm) return true;
        const term = benSystemSearchTerm.toLowerCase();
        const facilityHay = `${group.facilityName} ${group.facilityArea} ${group.facilityType}`.toLowerCase();
        const jfaHay = group.jfas.map((jfa) => `${jfa.name} ${jfa.team}`.toLowerCase()).join(' ');
        return facilityHay.includes(term) || jfaHay.includes(term);
    });
    const headers = ['Facility', 'Area', 'Type', 'JFA Name', 'Team'];
    const rows = [];
    filtered.forEach((group) => {
        group.jfas
            .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }))
            .forEach((jfa) => {
                rows.push([group.facilityName, group.facilityArea || '—', group.facilityType || 'Facility', jfa.name, jfa.team || '—']);
            });
    });
    const ok = exportPdfWithHeaders(headers, rows, `ben-system-${todayKey()}.pdf`, 'Ben System Export');
    if (ok) {
        openBenExportModal(`PDF export window opened. ${rows.length} row(s) were included.`);
    }
}

function renderBenSystemPage() {
    const body = document.getElementById('benSystemBody');
    const summary = document.getElementById('benSystemSummary');
    const chip = document.getElementById('benSystemScopeChip');
    if (!body) return;
    const grouped = getBenSystemGroupedData();
    const totalJfas = grouped.reduce((sum, item) => sum + item.jfas.length, 0);
    const teamCount = new Set(grouped.flatMap((item) => item.jfas.map((jfa) => jfa.team))).size;
    const busiest = grouped[0];
    const today = todayKey();
    const scopeLabel = adminRole === 'ADMIN'
        ? 'Admin (All Teams)'
        : adminRole === 'TEAM'
            ? adminTeam
            : `${getLeadIdentity()?.team || 'All Teams'}`;
    if (chip) chip.textContent = `${scopeLabel} • ${today}`;
    const filtered = grouped.filter((group) => {
        if (!benSystemSearchTerm) return true;
        const term = benSystemSearchTerm.toLowerCase();
        const facilityHay = `${group.facilityName} ${group.facilityArea} ${group.facilityType}`.toLowerCase();
        const jfaHay = group.jfas.map((jfa) => `${jfa.name} ${jfa.team}`.toLowerCase()).join(' ');
        return facilityHay.includes(term) || jfaHay.includes(term);
    });
    if (summary) {
        summary.innerHTML = `
            <span class="insight-chip">Facilities Today: ${grouped.length}</span>
            <span class="insight-chip">JFAs Assigned: ${totalJfas}</span>
            <span class="insight-chip">Teams Covered: ${teamCount}</span>
            <span class="insight-chip">Highest Load: ${escapeHtml(busiest?.facilityName || '—')} (${busiest?.jfas.length || 0})</span>
            ${benSystemSearchTerm ? `<span class="insight-chip">Filtered: ${filtered.length}</span>` : ''}
        `;
    }
    if (!grouped.length) {
        body.innerHTML = `
            <div class="insight-card">
                <p class="menu-page-note ben-system-secondary-note">No facility assignments captured for today yet.</p>
                <div class="menu-page-actions">
                    <button class="action-btn secondary" type="button" onclick="navigateToAssignment()">Open Assignment</button>
                    <button class="action-btn secondary" type="button" onclick="openMenuPage('admin', true, true)">Open Admin Team Portal</button>
                </div>
            </div>
        `;
        return;
    }
    if (!filtered.length) {
        body.innerHTML = `
            <div class="insight-card">
                <p class="menu-page-note ben-system-secondary-note">No Ben System matches for your search.</p>
                <div class="menu-page-actions">
                    <button class="action-btn secondary" type="button" onclick="clearBenSystemSearch()">Clear Search</button>
                </div>
            </div>
        `;
        return;
    }
    const rows = filtered.map((group, index) => `
        <article class="facility-card ben-facility-card">
            <div class="assignment-badge">FACILITY ${index + 1}</div>
            <h4>${escapeHtml(group.facilityName)}</h4>
            <p class="page-subtitle">${escapeHtml(group.facilityType || 'Facility')} • ${escapeHtml(group.facilityArea || 'Area not set')}</p>
            <div class="menu-page-note ben-system-section-title" style="margin:8px 0 8px;">Assigned JFAs</div>
            <div class="mini-table">
                <table>
                    <thead>
                        <tr>
                            <th>JFA Name</th>
                            <th>Team</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${group.jfas
                            .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }))
                            .map((jfa) => `
                                <tr>
                                    <td>${escapeHtml(jfa.name)}</td>
                                    <td>${escapeHtml(jfa.team)}</td>
                                </tr>
                            `).join('')}
                    </tbody>
                </table>
            </div>
        </article>
    `).join('');
    body.innerHTML = `
        <div class="menu-page-note ben-system-secondary-note">Grouped by facility for quick tracking of where each JFA is working today.</div>
        <div class="dashboard-grid">
            ${rows}
        </div>
    `;
}

function renderPaymentsPage() {
    const body = document.getElementById('paymentsBody');
    const chip = document.getElementById('paymentsScopeChip');
    const summary = document.getElementById('paymentsSummary');
    const tabButtons = document.querySelectorAll('[data-payments-tab]');
    if (!body) return;
    tabButtons.forEach((btn) => {
        const tab = btn.getAttribute('data-payments-tab');
        const isActive = tab === paymentsTab;
        btn.classList.toggle('is-active', isActive);
        btn.classList.toggle('secondary', !isActive);
    });
    if (chip) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
        chip.textContent = `${label || 'Personal'} • ${paymentsTab.charAt(0).toUpperCase()}${paymentsTab.slice(1)}`;
    }
    const leads = getPaymentsScopedLeads();
    const counts = {
        Pending: leads.filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Pending').length,
        Unsuccessful: leads.filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Unsuccessful').length,
        Successful: leads.filter((lead) => normalizePaymentStatus(lead.paymentStatus) === 'Successful').length
    };
    if (summary) {
        summary.innerHTML = `
            <span class="insight-chip">Pending: ${counts.Pending}</span>
            <span class="insight-chip">Unsuccessful: ${counts.Unsuccessful}</span>
            <span class="insight-chip">Successful: ${counts.Successful}</span>
        `;
    }
    const filtered = leads.filter((lead) => {
        const status = normalizePaymentStatus(lead.paymentStatus);
        if (paymentsTab === 'pending') return status === 'Pending';
        if (paymentsTab === 'unsuccessful') return status === 'Unsuccessful';
        return status === 'Successful';
    }).filter((lead) => {
        if (!paymentsSearchTerm) return true;
        const term = paymentsSearchTerm.toLowerCase();
        const name = String(lead.clientName || '').toLowerCase();
        const lid = String(lead.leadId || '').toLowerCase();
        return name.includes(term) || lid.includes(term);
    });
    if (!filtered.length) {
        body.innerHTML = `
            <p class="menu-page-note">No ${paymentsTab} leads available.</p>
            <div class="insight-list">
                <span class="insight-chip">Pending: submitted and still processing</span>
                <span class="insight-chip">Unsuccessful: not converted (reason required)</span>
                <span class="insight-chip">Successful: converted (commission date shown)</span>
            </div>
        `;
        return;
    }
    const list = filtered
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
        .map((lead) => {
            const leadId = lead.leadId || '—';
            const isAdmin = adminRole === 'ADMIN';
            const clientName = isAdmin ? (lead.clientNameRaw || lead.clientName || '—') : (lead.clientName || '—');
            const clientCell = lead.clientCellRaw || lead.clientCell || '';
            const clientEmail = lead.clientEmailRaw || lead.clientEmail || '';
            const clientAddress = lead.clientAddressRaw || lead.clientAddress || '';
            const reason = lead.failureReason || '—';
            const commission = lead.commissionDate || '—';
            return `
                <div class="payment-card">
                    <h4>${escapeHtml(clientName)}</h4>
                    <div class="payment-meta">
                        <span>LID ${escapeHtml(leadId)}</span>
                        <button class="copy-btn" type="button" onclick="copyToClipboard('${escapeHtml(leadId)}','LID copied')">Copy LID</button>
                        <span>${escapeHtml(formatJfaName(lead.jfaName || ''))}</span>
                        <span>${escapeHtml(lead.jfaTeam || '—')}</span>
                    </div>
                    <p class="page-subtitle"><strong>Status:</strong> ${escapeHtml(normalizePaymentStatus(lead.paymentStatus))}</p>
                    ${isAdmin ? `
                        <p class="page-subtitle"><strong>Contact:</strong> ${escapeHtml(clientCell || '—')} • ${escapeHtml(clientEmail || '—')}</p>
                        <p class="page-subtitle"><strong>Address:</strong> ${escapeHtml(clientAddress || '—')}</p>
                    ` : ''}
                    ${paymentsTab === 'unsuccessful' ? `<p class="page-subtitle"><strong>Reason:</strong> ${escapeHtml(reason)}</p>` : ''}
                    ${paymentsTab === 'successful' ? `<p class="page-subtitle"><strong>Commission Date:</strong> ${escapeHtml(commission)}</p>` : ''}
                </div>
            `;
        })
        .join('');
    body.innerHTML = `<div class="payments-list">${list}</div>`;
}

function renderMasterFacilitiesEditor() {
    try {
        const source = Array.isArray(facilities) ? facilities : [];
        const list = source
            .filter((facility) => facility && typeof facility === 'object')
            .sort((a, b) => String(a?.name || '').localeCompare(String(b?.name || ''), 'en', { sensitivity: 'base' }));
        if (!list.length) return '<p class="page-subtitle">No facilities found.</p>';
        return `
        <div class="insight-card">
            <h4>Edit Facilities</h4>
            <p class="page-subtitle">Edit name, contact person, phone, area and type. Remove facilities that are no longer productive.</p>
            <div class="mini-table admin-facility-editor-table-wrap">
                <table class="facility-editor-table mobile-stack-table">
                    <thead>
                        <tr>
                            <th>Facility</th>
                            <th>Type</th>
                            <th>Location</th>
                            <th>Contact Person</th>
                            <th>Contact Number</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${list.map((facility) => `
                            <tr>
                                <td data-label="Facility"><input type="text" id="mf-name-${facility.id}" value="${escapeHtml(facility.name || '')}"></td>
                                <td data-label="Type"><input type="text" id="mf-type-${facility.id}" value="${escapeHtml(facility.type || 'Other')}"></td>
                                <td data-label="Location"><input type="text" id="mf-area-${facility.id}" value="${escapeHtml(facility.area || '')}"></td>
                                <td data-label="Contact Person"><input type="text" id="mf-contact-${facility.id}" value="${escapeHtml(facility.contact || 'Receptionist')}"></td>
                                <td data-label="Contact Number"><input type="text" id="mf-phone-${facility.id}" value="${escapeHtml(facility.phone || 'N/A')}"></td>
                                <td data-label="Actions">
                                    <div class="facility-inline-actions">
                                        <button class="action-btn secondary" type="button" onclick="saveMasterFacilityEdit(${facility.id})">Save</button>
                                        <button class="action-btn secondary" type="button" onclick="removeMasterFacility(${facility.id})">Remove</button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            <div class="menu-page-subsection" style="margin-top:12px;">
                <h3>Add Another Facility</h3>
                <div class="master-capture-grid">
                    <div class="form-group">
                        <label for="mf-new-name">Facility Name</label>
                        <input type="text" id="mf-new-name" placeholder="e.g. Newtown Clinic">
                    </div>
                    <div class="form-group">
                        <label for="mf-new-type">Type</label>
                        <input type="text" id="mf-new-type" placeholder="Auto-detect if left blank">
                    </div>
                    <div class="form-group">
                        <label for="mf-new-area">Location</label>
                        <input type="text" id="mf-new-area" placeholder="e.g. Johannesburg">
                    </div>
                    <div class="form-group">
                        <label for="mf-new-contact">Contact Person</label>
                        <input type="text" id="mf-new-contact" placeholder="Default: Receptionist">
                    </div>
                    <div class="form-group">
                        <label for="mf-new-phone">Contact Number</label>
                        <input type="text" id="mf-new-phone" placeholder="Default: N/A">
                    </div>
                </div>
                <div class="menu-page-actions" style="margin-top:8px;">
                    <button class="action-btn" type="button" onclick="addMasterFacilityFromEditor()">Add Facility</button>
                </div>
            </div>
        </div>
    `;
    } catch (error) {
        console.error('renderMasterFacilitiesEditor failed:', error);
        return `
            <div class="insight-card">
                <h4>Edit Facilities</h4>
                <p class="page-subtitle">Facility editor could not load due to invalid data. Refresh, then try again.</p>
            </div>
        `;
    }
}

function saveMasterFacilityEdit(id) {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) return;
    const facility = getFacilityById(id);
    if (!facility) return;
    const previous = {
        name: facility.name || '',
        type: facility.type || '',
        area: facility.area || '',
        contact: facility.contact || '',
        phone: facility.phone || ''
    };
    const name = document.getElementById(`mf-name-${id}`)?.value?.trim() || facility.name;
    const type = document.getElementById(`mf-type-${id}`)?.value?.trim() || facility.type || 'Other';
    const area = document.getElementById(`mf-area-${id}`)?.value?.trim() || '';
    const contact = document.getElementById(`mf-contact-${id}`)?.value?.trim() || 'Receptionist';
    const phone = document.getElementById(`mf-phone-${id}`)?.value?.trim() || 'N/A';
    facility.name = name;
    facility.type = type;
    facility.area = area;
    facility.contact = contact;
    facility.phone = phone;
    sortFacilitiesAlphabetically();
    saveFacilityDirectory();
    saveFacilityStats();
    populateFacilityDropdown();
    renderFacilityOptions(document.getElementById('facilityFilter')?.value || '');
    renderAdminMasterLogger();
    renderFacilityDirectory();
    const changes = [];
    if (previous.name !== name) changes.push(`name: ${previous.name || '—'} -> ${name || '—'}`);
    if (previous.type !== type) changes.push(`type: ${previous.type || '—'} -> ${type || '—'}`);
    if (previous.area !== area) changes.push(`location: ${previous.area || '—'} -> ${area || '—'}`);
    if (previous.contact !== contact) changes.push(`contact: ${previous.contact || '—'} -> ${contact || '—'}`);
    if (previous.phone !== phone) changes.push(`phone: ${previous.phone || '—'} -> ${phone || '—'}`);
    if (changes.length) {
        logAudit('Facility updated', `${facility.id} • ${changes.join(' | ')} • by ${getAuditActorLabel()}`);
    }
    showToast('Facility updated.', 'success');
}

function removeMasterFacility(id) {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) return;
    const facility = getFacilityById(id);
    if (!facility) return;
    const input = prompt(`Type REMOVE to disable "${facility.name}" from all facility lists.`);
    if (input !== 'REMOVE') {
        showToast('Remove cancelled.', 'error');
        return;
    }
    disabledFacilityKeys.add(normalizeFacilityName(facility.name));
    scheduleStorageWrite(STORAGE_KEYS.disabledFacilities, JSON.stringify([...disabledFacilityKeys]));
    const idx = facilities.findIndex((f) => f.id === id);
    if (idx >= 0) facilities.splice(idx, 1);
    rebuildFacilityIndex();
    saveFacilityDirectory();
    saveFacilityStats();
    const custom = JSON.parse(localStorage.getItem(STORAGE_KEYS.customFacilities) || '[]');
    const filtered = custom.filter((item) => normalizeFacilityName(item.name) !== normalizeFacilityName(facility.name));
    scheduleStorageWrite(STORAGE_KEYS.customFacilities, JSON.stringify(filtered));
    populateFacilityDropdown();
    renderFacilityOptions(document.getElementById('facilityFilter')?.value || '');
    renderAdminMasterLogger();
    renderFacilityDirectory();
    logAudit('Facility removed', `${facility.id} • ${facility.name} • by ${getAuditActorLabel()}`);
    showToast('Facility removed from active lists.', 'success');
}

function addMasterFacilityFromEditor() {
    if (adminRole !== 'ADMIN' || !hasAppPermission('admin')) return;
    const name = document.getElementById('mf-new-name')?.value?.trim() || '';
    const typeInput = document.getElementById('mf-new-type')?.value?.trim() || '';
    const area = document.getElementById('mf-new-area')?.value?.trim() || '';
    const contact = document.getElementById('mf-new-contact')?.value?.trim() || 'Receptionist';
    const phone = document.getElementById('mf-new-phone')?.value?.trim() || 'N/A';

    if (!name) {
        showToast('Please enter a facility name.', 'error');
        return;
    }
    const normalizedName = normalizeFacilityName(name);
    if (!normalizedName) {
        showToast('Please enter a valid facility name.', 'error');
        return;
    }
    if (facilities.some((facility) => normalizeFacilityName(facility.name) === normalizedName)) {
        showToast('That facility already exists.', 'error');
        return;
    }

    const nextId = facilities.reduce((max, facility) => Math.max(max, Number(facility.id) || 0), 0) + 1;
    const facility = {
        id: nextId,
        name: expandFacilityName(name),
        type: typeInput || detectFacilityType(name),
        area,
        contact,
        phone,
        allocations: 0,
        visits: [],
        consentForms: 0,
        hasDayRules: false
    };
    facilities.push(facility);
    saveCustomFacility(facility);
    disabledFacilityKeys.delete(normalizedName);
    scheduleStorageWrite(STORAGE_KEYS.disabledFacilities, JSON.stringify([...disabledFacilityKeys]));
    saveFacilityDirectory();
    saveFacilityStats();
    populateFacilityDropdown();
    renderFacilityOptions(document.getElementById('facilityFilter')?.value || '');
    renderAdminMasterLogger();
    renderFacilityDirectory();
    logAudit('Facility added', `${facility.id} • ${facility.name} (${facility.type || 'Other'}) • by ${getAuditActorLabel()}`);
    showToast('Facility added successfully.', 'success');
}

function renderMasterJfaRegisterEditor() {
    const list = getCompanyJfaDirectory();
    return `
        <div class="insight-card register-editor-panel">
            <h4>JFA Register (All)</h4>
            <p class="page-subtitle">Master Logger keeps and captures records for all JFAs in the company. Team leaders are automatically excluded.</p>
            <div class="master-capture-grid">
                <div class="form-group">
                    <label for="masterCaptureName">Full Name</label>
                    <input type="text" id="masterCaptureName" placeholder="e.g. Nkululeko Nkosi">
                </div>
                <div class="form-group">
                    <label for="masterCaptureTeam">Team</label>
                    <input type="text" id="masterCaptureTeam" placeholder="e.g. Team Thato">
                </div>
                <div class="form-group">
                    <label for="masterCapturePhone">Phone</label>
                    <input type="text" id="masterCapturePhone" placeholder="Optional">
                </div>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="captureMasterJfaRecord()">Capture JFA Record</button>
                <button class="action-btn secondary" type="button" onclick="exportMasterJfaRegister()">Download JFA Register</button>
                <button class="action-btn secondary" type="button" onclick="toggleAllRegisterAccountAccess('jfa', true)">Enable All JFAs</button>
                <button class="action-btn secondary" type="button" onclick="toggleAllRegisterAccountAccess('jfa', false)">Disable All JFAs</button>
            </div>
            ${list.length ? `
            <div class="admin-jfa-list">
                ${list.map((entry) => `
                    <div class="admin-jfa-card" data-source="master" data-name="${escapeHtml(entry.name)}" onclick="openMasterJfaProfile('${escapeHtml(entry.name)}')">
                        <div>
                            <strong>${escapeHtml(entry.name)}</strong>
                            <div class="page-subtitle">${escapeHtml(entry.team || 'No Team')}</div>
                        </div>
                        <div style="display:grid; gap:8px; justify-items:end;">
                            <span class="admin-jfa-status ${entry.presentToday ? 'on' : 'under'}">${entry.presentToday ? 'Present' : 'Absent'}</span>
                            ${renderRegisterAccountAccessSwitch('jfa', entry.key, entry.name, '', '')}
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : '<p class="page-subtitle">No JFAs captured yet.</p>'}
            <div class="admin-detail-section" id="masterJfaProfileDetail"></div>
        </div>
    `;
}

function captureMasterJfaRecord() {
    if (adminRole !== 'ADMIN') return;
    const nameEl = document.getElementById('masterCaptureName');
    const teamEl = document.getElementById('masterCaptureTeam');
    const phoneEl = document.getElementById('masterCapturePhone');
    if (!nameEl || !teamEl || !phoneEl) return;
    const fullName = formatJfaName(nameEl.value || '');
    const team = (teamEl.value || '').trim();
    const phone = (phoneEl.value || '').trim();
    if (!fullName) {
        showToast('Full name is required.', 'error');
        nameEl.focus();
        return;
    }
    const key = normalizeJfaName(fullName);
    const profile = ensureJfaProfile(fullName, { team, phone }) || {};
    profile.fullName = fullName;
    if (team) profile.team = team;
    if (phone) profile.phone = phone;
    jfaProfiles[key] = profile;
    saveJfaProfiles();

    const today = todayKey();
    const existingToday = jfaRecords.find((record) =>
        normalizeJfaName(record.name) === key && recordDateKey(record) === today
    );
    if (existingToday) {
        if (team) existingToday.team = team;
        if (phone) existingToday.phone = phone;
    } else {
        jfaRecords.push({
            id: `master-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            name: fullName,
            phone: phone || profile.phone || '',
            team: team || profile.team || '',
            facility: null,
            consentForms: 0,
            productive: 'NO',
            notes: 'Captured by Master Logger',
            timestamp: new Date().toISOString()
        });
    }
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    logAudit('Master Logger captured JFA', `${fullName} (${team || 'No Team'})`);

    nameEl.value = '';
    teamEl.value = '';
    phoneEl.value = '';
    renderAdminMasterLogger();
    refreshTeamSelectOptions();
    renderAdminTeamDetails();
    updateStatistics();
    updateSummary();
    showToast('JFA captured in Master Logger register.', 'success');
}

function openMasterJfaProfile(name) {
    if (adminRole !== 'ADMIN') return;
    const detail = document.getElementById('masterJfaProfileDetail');
    if (!detail) return;
    const records = jfaRecords.filter((r) => normalizeJfaName(r.name) === normalizeJfaName(name));
    const latest = records.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))[0] || {};
    const profile = ensureJfaProfile(name, { phone: latest.phone || '', team: latest.team || '' });
    saveJfaProfiles();
    const key = normalizeJfaName(name);
    detail.innerHTML = `
        <div class="insight-card register-editor-panel">
            <h4>${escapeHtml(formatJfaName(name))} • Personal Info</h4>
            <p class="page-subtitle">Complete this profile and press Capture to save the record.</p>
            <div class="mini-table">
                <table>
                    <tbody>
                        ${renderProfileSectionRow('Personal Details')}
                        ${renderProfileFieldRow('Name', `mp-name-${key}`, profile.name)}
                        ${renderProfileFieldRow('Surname', `mp-surname-${key}`, profile.surname)}
                        ${renderProfileFieldRow('Team', `mp-team-${key}`, profile.team || latest.team || '')}
                        ${renderProfileSectionRow('Contact Details')}
                        ${renderProfileFieldRow('Phone Number', `mp-phone-${key}`, profile.phone)}
                        ${renderProfileFieldRow('Email', `mp-email-${key}`, profile.email)}
                        ${renderProfileSectionRow('Address')}
                        ${renderProfileFieldRow('Physical Address', `mp-address-${key}`, profile.address)}
                        ${renderProfileSectionRow('Banking Details')}
                        ${renderProfileFieldRow('Bank Name', `mp-bank-${key}`, profile.bankName)}
                        ${renderProfileFieldRow('Account Number', `mp-account-${key}`, profile.accountNumber)}
                        ${renderProfileFieldRow('Branch Code', `mp-branch-${key}`, profile.branchCode)}
                        ${renderProfileSectionRow('Compliance')}
                        ${renderProfileFieldRow('Tax Number', `mp-tax-${key}`, profile.taxNumber)}
                        ${renderProfileSectionRow('Next of Kin')}
                        ${renderProfileFieldRow('Next of Kin Name', `mp-nok-name-${key}`, profile.nextOfKinName)}
                        ${renderProfileFieldRow('Next of Kin Phone', `mp-nok-phone-${key}`, profile.nextOfKinPhone)}
                        ${renderProfileFieldRow('Relationship', `mp-nok-rel-${key}`, profile.nextOfKinRelationship)}
                    </tbody>
                </table>
            </div>
            <div class="menu-page-actions">
                <button class="action-btn" type="button" onclick="saveMasterJfaProfile('${escapeHtml(name)}')">Capture</button>
                <button class="action-btn secondary" type="button" onclick="exportMasterJfaProfile('${escapeHtml(name)}')">Download JFA Record</button>
            </div>
        </div>
    `;
    highlightInlineSelection('master');
}

function renderProfileFieldRow(label, id, value) {
    return `<tr><th>${label}</th><td><input type="text" id="${id}" value="${escapeHtml(value || '')}"></td></tr>`;
}

function renderProfileSectionRow(title) {
    return `<tr><th colspan="2">${escapeHtml(title)}</th></tr>`;
}

function saveMasterJfaProfile(name) {
    if (adminRole !== 'ADMIN') return;
    const key = normalizeJfaName(name);
    const profile = ensureJfaProfile(name) || {};
    const read = (suffix) => document.getElementById(`mp-${suffix}-${key}`)?.value?.trim() || '';
    profile.name = read('name');
    profile.surname = read('surname');
    profile.phone = read('phone');
    profile.email = read('email');
    profile.address = read('address');
    profile.bankName = read('bank');
    profile.accountNumber = read('account');
    profile.branchCode = read('branch');
    profile.taxNumber = read('tax');
    profile.nextOfKinName = read('nok-name');
    profile.nextOfKinPhone = read('nok-phone');
    profile.nextOfKinRelationship = read('nok-rel');
    profile.team = read('team');
    profile.fullName = formatJfaName(`${profile.name} ${profile.surname}`.trim() || name);
    jfaProfiles[key] = profile;
    saveJfaProfiles();
    jfaRecords.forEach((record) => {
        if (normalizeJfaName(record.name) !== key) return;
        if (profile.phone) record.phone = profile.phone;
        if (profile.team) record.team = profile.team;
    });
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    logAudit('Master Logger captured JFA profile', `${formatJfaName(name)} profile captured`);
    showToast('JFA profile captured and saved.', 'success');
    renderAdminMasterLogger();
    refreshTeamSelectOptions();
    renderAdminTeamDetails();
    updateStatistics();
}

function exportMasterJfaProfile(name) {
    if (adminRole !== 'ADMIN') return;
    const profile = ensureJfaProfile(name) || {};
    const fullName = formatJfaName(profile.fullName || `${profile.name || ''} ${profile.surname || ''}`.trim() || name);
    const headers = [
        'Full Name',
        'Name',
        'Surname',
        'Team',
        'Phone Number',
        'Email Address',
        'Physical Address',
        'Bank Name',
        'Account Number',
        'Branch Code',
        'Tax Number',
        'Next of Kin Name',
        'Next of Kin Phone',
        'Next of Kin Relationship'
    ];
    const rows = [[
        fullName,
        profile.name || '',
        profile.surname || '',
        profile.team || '',
        profile.phone || '',
        profile.email || '',
        profile.address || '',
        profile.bankName || '',
        profile.accountNumber || '',
        profile.branchCode || '',
        profile.taxNumber || '',
        profile.nextOfKinName || '',
        profile.nextOfKinPhone || '',
        profile.nextOfKinRelationship || ''
    ]];
    const safe = normalizeJfaName(fullName).replace(/\s+/g, '-');
    exportCsvWithHeaders(headers, rows, `jfa-profile-${safe || 'record'}.csv`);
    logAudit('Exported JFA profile', `${fullName}`);
    logExportHistory(`JFA Profile Export: ${fullName}`, rows.length);
}

function exportMasterJfaRegister() {
    if (adminRole !== 'ADMIN') return;
    const rows = getCompanyJfaDirectory().map((entry) => {
        const profile = jfaProfiles[entry.key] || ensureJfaProfile(entry.name) || {};
        const split = splitJfaName(profile.fullName || entry.name || '');
        return [
            profile.name || split.name || '',
            profile.surname || split.surname || '',
            entry.presentToday ? 'Present' : 'Absent'
        ];
    });
    const headers = [
        'Name',
        'Surname',
        'Today Status'
    ];
    exportCsvWithHeaders(headers, rows, `master-jfa-register-private-${todayKey()}.csv`);
    logAudit('Exported JFA register (minimal)', `Rows: ${rows.length}`);
    logExportHistory('Master JFA Register Export', rows.length);
}

function renderMasterLearningEditor() {
    return `
        <div class="insight-card">
            <h4>Learning Hub Editor</h4>
            <p class="page-subtitle">Choose a topic, edit the training content, then save. This updates the live Learning page.</p>
            <div class="menu-page-actions">
                <select id="masterLearningTopic">
                    ${LEARNING_TOPIC_KEYS.map((key) => `<option value="${key}">${escapeHtml(getLearningTitle(key))}</option>`).join('')}
                </select>
                <button class="action-btn secondary" type="button" onclick="loadMasterLearningTopic()">Load Topic</button>
                <button class="action-btn secondary" type="button" onclick="resetMasterLearningTopic()">Reset to Default</button>
                <button class="action-btn" type="button" onclick="saveMasterLearningTopic()">Save Topic</button>
            </div>
            <div class="form-group" style="margin-top:12px;">
                <label for="masterLearningContent">Topic Content</label>
                <textarea id="masterLearningContent" rows="16" placeholder="Edit learning material content here..."></textarea>
            </div>
        </div>
    `;
}

function loadMasterLearningTopic() {
    if (adminRole !== 'ADMIN') return;
    const select = document.getElementById('masterLearningTopic');
    const textarea = document.getElementById('masterLearningContent');
    if (!select || !textarea) return;
    const key = select.value;
    textarea.value = getLearningContent(key);
}

function saveMasterLearningTopic() {
    if (adminRole !== 'ADMIN') return;
    const select = document.getElementById('masterLearningTopic');
    const textarea = document.getElementById('masterLearningContent');
    if (!select || !textarea) return;
    const key = select.value;
    const content = textarea.value.trim();
    if (!content) {
        showToast('Learning content cannot be empty.', 'error');
        return;
    }
    learningOverrides[key] = content;
    scheduleStorageWrite(STORAGE_KEYS.learningOverrides, JSON.stringify(learningOverrides));
    showToast(`${getLearningTitle(key)} updated.`, 'success');
    if (localStorage.getItem('lastLearningKey') === key) {
        showLearning(key);
    }
}

function resetMasterLearningTopic() {
    if (adminRole !== 'ADMIN') return;
    const select = document.getElementById('masterLearningTopic');
    const textarea = document.getElementById('masterLearningContent');
    if (!select || !textarea) return;
    const key = select.value;
    delete learningOverrides[key];
    scheduleStorageWrite(STORAGE_KEYS.learningOverrides, JSON.stringify(learningOverrides));
    textarea.value = getLearningContent(key);
    showToast(`${getLearningTitle(key)} restored to default.`, 'success');
    if (localStorage.getItem('lastLearningKey') === key) {
        showLearning(key);
    }
}

function renderMasterFormsEditor() {
    const items = [...formsLibrary];
    return `
        <div class="insight-card">
            <h4>Forms Library Editor</h4>
            <p class="page-subtitle">Add or edit forms visible in the Forms page. Use local file names or links.</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="addMasterForm()">Add Form</button>
                <button class="action-btn" type="button" onclick="saveMasterFormsLibrary()">Save Forms Library</button>
            </div>
            <div class="mini-table admin-forms-library-table-wrap">
                <table class="forms-library-table mobile-stack-table">
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Description</th>
                            <th>File / URL</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.map((form, idx) => `
                            <tr>
                                <td data-label="Title"><input type="text" id="mfm-title-${idx}" value="${escapeHtml(form.title || '')}"></td>
                                <td data-label="Description"><input type="text" id="mfm-desc-${idx}" value="${escapeHtml(form.description || '')}"></td>
                                <td data-label="File / URL"><input type="text" id="mfm-url-${idx}" value="${escapeHtml(form.url || '')}"></td>
                                <td data-label="Action"><button class="action-btn secondary" type="button" onclick="removeMasterForm(${idx})">Remove</button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function addMasterForm() {
    if (adminRole !== 'ADMIN') return;
    formsLibrary.push({
        id: `form-${Date.now()}`,
        title: 'New Form',
        description: 'Describe this form',
        url: ''
    });
    renderAdminMasterLogger();
}

function removeMasterForm(index) {
    if (adminRole !== 'ADMIN') return;
    if (!Number.isFinite(index) || index < 0 || index >= formsLibrary.length) return;
    formsLibrary.splice(index, 1);
    renderAdminMasterLogger();
}

function saveMasterFormsLibrary() {
    if (adminRole !== 'ADMIN') return;
    const next = [];
    for (let i = 0; i < formsLibrary.length; i++) {
        const title = document.getElementById(`mfm-title-${i}`)?.value?.trim() || '';
        const description = document.getElementById(`mfm-desc-${i}`)?.value?.trim() || '';
        const url = document.getElementById(`mfm-url-${i}`)?.value?.trim() || '';
        if (!title || !url) continue;
        next.push({
            id: formsLibrary[i].id || `form-${Date.now()}-${i}`,
            title,
            description,
            url
        });
    }
    formsLibrary = next;
    saveFormsLibrary();
    renderFormsLibrary();
    renderAdminMasterLogger();
    showToast('Forms library updated.', 'success');
}

function renderFacilityDirectory() {
    const container = document.getElementById(getAdminFacilityDirectoryContainerId());
    updateFacilityDirectoryToggleButton();
    if (!container) return;
    if (!adminFacilityDirectoryOpen) {
        container.style.display = 'none';
        container.innerHTML = '';
        return;
    }
    container.style.display = '';
    const isAdmin = adminRole === 'ADMIN';
    const list = facilities.filter((f) => allocationFacilityNames.has(normalizeFacilityName(f.name)));
    if (!list.length) {
        container.innerHTML = '<p class="menu-page-note">No facility directory entries.</p>';
        return;
    }
    container.innerHTML = `
        <div class="insight-card">
            <h4>Facility Directory</h4>
            <p class="page-subtitle">Contacts default to Receptionist. Phone numbers can be added later by admin only.</p>
            <div class="mini-table admin-facility-directory-table-wrap">
                <table class="facility-directory-table mobile-stack-table">
                    <thead>
                        <tr>
                            <th>Facility</th>
                            <th>Contact</th>
                            <th>Phone</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${list.map((facility) => `
                            <tr>
                                <td data-label="Facility">${escapeHtml(facility.name || '')}</td>
                                <td data-label="Contact">
                                    <input type="text" value="${escapeHtml(facility.contact || 'Receptionist')}" ${isAdmin ? '' : 'disabled'} data-fid="${facility.id}" data-field="contact" class="facility-edit-input">
                                </td>
                                <td data-label="Phone">
                                    <input type="text" value="${escapeHtml(facility.phone || 'N/A')}" ${isAdmin ? '' : 'disabled'} data-fid="${facility.id}" data-field="phone" class="facility-edit-input">
                                </td>
                                <td data-label="Status">${escapeHtml(facility.status || 'Active')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    if (isAdmin) {
        const inputs = container.querySelectorAll('.facility-edit-input');
        inputs.forEach((input) => {
            input.addEventListener('change', () => {
                const id = parseInt(input.getAttribute('data-fid'), 10);
                const field = input.getAttribute('data-field');
                const facility = getFacilityById(id);
                if (!facility || !field) return;
                const value = input.value.trim() || (field === 'contact' ? 'Receptionist' : 'N/A');
                facility[field] = value;
                saveFacilityDirectory();
                showToast('Facility updated.', 'success');
            });
        });
    }
}

function updateFacilityDirectoryToggleButton() {
    const ids = ['adminFacilityDirectoryBtn', 'adminStandaloneFacilityDirectoryBtn'];
    ids.forEach((id) => {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.textContent = adminFacilityDirectoryOpen ? 'Hide Facility Directory' : 'Facility Directory';
    });
}

function toggleFacilityDirectory(forceOpen = null) {
    if (adminRole === 'PERSONAL') {
        showToast('Select team/admin scope first.', 'error');
        return;
    }
    adminFacilityDirectoryOpen = forceOpen == null ? !adminFacilityDirectoryOpen : Boolean(forceOpen);
    renderFacilityDirectory();
    if (adminFacilityDirectoryOpen) {
        document.getElementById(getAdminFacilityDirectoryContainerId())?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function openAdminJfaDetail(name, source = 'admin', forceOpen = false) {
    const inlineAdmin = document.getElementById('adminJfaInlineDetail');
    const inlineTeam = document.getElementById('teamDetailInlineDetail');
    const bodyEl = source === 'team' ? inlineTeam : inlineAdmin;
    if (!bodyEl) return;
    const normalized = normalizeJfaName(name);
    if (!forceOpen && activeInlineDetail[source] === normalized) {
        bodyEl.innerHTML = '';
        activeInlineDetail[source] = null;
        highlightInlineSelection(source);
        return;
    }
    let allRecords = jfaRecords.filter((r) => normalizeJfaName(r.name) === normalized);
    if (adminRole === 'TEAM' && adminTeam) {
        allRecords = allRecords.filter((r) => r.team === adminTeam);
    }
    if (adminRole === 'PERSONAL' && currentJFA?.name) {
        allRecords = allRecords.filter((r) => normalizeJfaName(r.name) === normalizeJfaName(currentJFA.name));
    }
    if (!allRecords.length) {
        showToast('No accessible records found for that JFA in your scope.', 'error');
        return;
    }
    const team = allRecords[0]?.team || '—';
    const totalForms = allRecords.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const today = todayKey();
    const todayForms = allRecords.filter((r) => recordDateKey(r) === today).reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const monthStart = getStartOfMonth(new Date());
    let monthRecords = [
        ...getArchiveRangeRecords(monthStart, new Date()),
        ...jfaRecords.filter((r) => r.timestamp)
    ].filter((r) => normalizeJfaName(r.name) === normalized);
    if (adminRole === 'TEAM' && adminTeam) {
        monthRecords = monthRecords.filter((r) => r.team === adminTeam);
    }
    const monthForms = monthRecords.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const workingDays = getWorkingDays(monthStart, new Date());
    const presentDays = new Set(monthRecords.map((r) => recordDateKey(r)).filter(Boolean));
    const absences = Math.max(0, workingDays.length - presentDays.size);
    const leadStats = getJfaLeadStats(name, team);
    const recentSeries = getRecentWorkdaySeries(monthRecords, 5);
    const underStreak = getConsecutiveUnderDays(recentSeries, CONFIG.DAILY_TARGET);
    const isTeamLeader = isTeamLeaderName(name, team);
    const perf = getPerformanceBand(todayForms, monthForms);
    const needsAssistance = !isTeamLeader && perf.code === 'under' && underStreak >= 3;

    const last7 = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(now.getDate() - i);
        const key = dateKeyLocal(d);
        const dayTotal = monthRecords.filter((r) => recordDateKey(r) === key).reduce((sum, r) => sum + (r.consentForms || 0), 0);
        last7.push({ key, value: dayTotal, label: d.toLocaleDateString('en-ZA', { weekday: 'short' }) });
    }
    const max = Math.max(1, ...last7.map((d) => d.value));

    const canEdit = adminRole === 'ADMIN' || (adminRole === 'TEAM' && team === adminTeam);
    const inputId = source === 'team' ? 'adminConfirmFormsTeam' : 'adminConfirmFormsAdmin';
    const noteInputId = source === 'team' ? 'interventionNoteTeam' : 'interventionNoteAdmin';
    const followInputId = source === 'team' ? 'interventionFollowTeam' : 'interventionFollowAdmin';
    const statusInputId = source === 'team' ? 'interventionStatusTeam' : 'interventionStatusAdmin';
    const weekly = getWeeklyFeedbackFor(name).filter((entry) => adminRole !== 'TEAM' || !adminTeam || entry.team === adminTeam);
    const weeklyArchived = getArchivedWeeklyFeedbackFor(name).map((bucket) => ({
        ...bucket,
        entries: (bucket.entries || []).filter((entry) => adminRole !== 'TEAM' || !adminTeam || entry.team === adminTeam)
    })).filter((bucket) => bucket.entries.length);
    const interventions = getInterventionEntries(name, team);
    const openInterventions = interventions.filter((entry) => entry.status !== 'Closed').length;
    const lastIntervention = interventions[0] || null;
    const teamRoster = buildTeamRoster(team).filter((entry) => !entry.isTeamLeader);
    const teamDailyTarget = teamRoster.length * CONFIG.DAILY_TARGET;
    const teamFormsToday = teamRoster.reduce((sum, entry) => sum + (entry.formsToday || 0), 0);
    const teamTargetGap = Math.max(0, teamDailyTarget - teamFormsToday);
    bodyEl.innerHTML = `
        <div class="insight-card">
            <h4>${formatJfaName(name)} • ${team}</h4>
        </div>
        <div class="insight-card">
            <h4>Performance</h4>
            <div class="insight-list">
                <span class="insight-chip">Today: ${todayForms}</span>
                <span class="insight-chip">Month: ${monthForms}</span>
                <span class="insight-chip">All Time: ${totalForms}</span>
                <span class="insight-chip">Leads Today: ${leadStats.today}</span>
                <span class="insight-chip">Leads Month: ${leadStats.month}</span>
                <span class="insight-chip ${needsAssistance ? 'danger' : ''}">Status: ${isTeamLeader ? 'Team Leader' : perf.label}</span>
                <span class="insight-chip ${needsAssistance ? 'danger' : ''}">Underperforming Streak: ${isTeamLeader ? 'N/A (Team Leader)' : `${underStreak} days`}</span>
                <span class="insight-chip">Absences: ${absences}</span>
                ${isTeamLeader ? `<span class="insight-chip ${teamTargetGap > 0 ? 'danger' : ''}">Team Target Gap: ${teamTargetGap}</span>` : ''}
            </div>
        </div>
        <div class="insight-card">
            <h4>Leader Guidance</h4>
            <p class="page-subtitle ${needsAssistance ? 'danger-text' : ''}">
                ${isTeamLeader
                    ? (teamTargetGap > 0
                        ? `Team is below target by ${teamTargetGap} forms today. Coach underperforming JFAs.`
                        : 'Team is on target. Keep supporting execution quality and consistency.')
                    : (needsAssistance
                        ? `${escapeHtml(formatJfaName(name))} is headed the wrong direction and needs assistance immediately before job-risk escalates.`
                        : `${escapeHtml(formatJfaName(name))} is currently stable. Continue coaching and daily check-ins.`)}
            </p>
            <div class="insight-list">
                <span class="insight-chip ${openInterventions ? 'danger' : ''}">Open Interventions: ${openInterventions}</span>
                <span class="insight-chip">Last Intervention: ${lastIntervention ? new Date(lastIntervention.timestamp).toLocaleString('en-ZA') : 'None logged'}</span>
            </div>
        </div>
        <div class="insight-card">
            <h4>7-Day Trend</h4>
            <div class="admin-graph">
                ${last7.map((d) => {
                    const height = Math.max(6, Math.round((d.value / max) * 100));
                    return `<div class="admin-graph-bar" style="height:${height}%"><span>${d.label}</span></div>`;
                }).join('')}
            </div>
        </div>
        <div class="insight-card">
            <h4>Verify Consent Forms</h4>
            <p class="page-subtitle">Only authorized team leaders/admin can confirm today's final total (physical paper forms + digital leads).</p>
            <div class="insight-list">
                <span class="insight-chip">Digital Leads (Auto): ${leadStats.today}</span>
                <span class="insight-chip">Current Total: ${todayForms}</span>
                <span class="insight-chip">Current Physical: ${Math.max(0, todayForms - leadStats.today)}</span>
            </div>
            <div class="menu-page-actions">
                <input type="number" id="${inputId}" min="${Math.max(0, leadStats.today)}" value="${todayForms}" placeholder="Enter final total (>= ${Math.max(0, leadStats.today)})" ${canEdit ? '' : 'disabled'}>
                <button class="action-btn" type="button" onclick="confirmConsentForms('${escapeHtml(name)}','${inputId}','${source}')" ${canEdit ? '' : 'disabled'}>Confirm Final Total</button>
            </div>
        </div>
        ${isTeamLeader ? '' : `
        <div class="insight-card">
            <h4>Intervention Tracker</h4>
            <p class="page-subtitle">Use this when a JFA is continuously underperforming and needs support before disciplinary escalation.</p>
            <div class="intervention-form">
                <textarea id="${noteInputId}" class="intervention-note" rows="3" placeholder="Log coaching/support action..." ${canEdit ? '' : 'disabled'}></textarea>
                <div class="intervention-row">
                    <label for="${followInputId}">Follow-up date</label>
                    <input type="date" id="${followInputId}" ${canEdit ? '' : 'disabled'}>
                    <label for="${statusInputId}">Case status</label>
                    <select id="${statusInputId}" class="intervention-status-select" ${canEdit ? '' : 'disabled'}>
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Closed">Closed</option>
                    </select>
                    <button class="action-btn" type="button" onclick="logJfaIntervention('${escapeHtml(name)}','${source}','${noteInputId}','${followInputId}','${statusInputId}')" ${canEdit ? '' : 'disabled'}>Log Intervention</button>
                </div>
            </div>
            ${interventions.length ? `
                <div class="mini-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Logged At</th>
                                <th>Status</th>
                                <th>Follow-up</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${interventions.map((entry) => `
                                <tr>
                                    <td>${entry.timestamp ? new Date(entry.timestamp).toLocaleString('en-ZA') : '—'}</td>
                                    <td>${escapeHtml(entry.status || 'Open')}</td>
                                    <td>${escapeHtml(entry.followUpDate || '—')}</td>
                                    <td>${escapeHtml(entry.note || '')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle">No intervention logs captured yet.</p>'}
        </div>
        `}
        <div class="insight-card">
            <h4>DBD Feedback (Daily Entries - This Week)</h4>
            ${weekly.length ? `
                <div class="mini-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Forms</th>
                                <th>Productive</th>
                                <th>Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${weekly.map((entry) => `
                                <tr>
                                    <td>${entry.date || '—'}</td>
                                    <td>${entry.consentForms || 0}</td>
                                    <td>${entry.productive || '—'}</td>
                                    <td>${escapeHtml(entry.notes || '')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p class="page-subtitle">No feedback captured this week.</p>'}
        </div>
        <div class="insight-card">
            <h4>DBD Feedback (Archived Weekly Logs)</h4>
            ${weeklyArchived.length ? weeklyArchived.map((bucket) => `
                <div class="page-subtitle">Week of ${bucket.weekKey}</div>
                <div class="mini-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Forms</th>
                                <th>Productive</th>
                                <th>Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${bucket.entries.map((entry) => `
                                <tr>
                                    <td>${entry.date || '—'}</td>
                                    <td>${entry.consentForms || 0}</td>
                                    <td>${entry.productive || '—'}</td>
                                    <td>${escapeHtml(entry.notes || '')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `).join('') : '<p class="page-subtitle">No archived feedback yet.</p>'}
        </div>
        ${adminRole === 'ADMIN' ? `
        <div class="insight-card">
            <h4>Lead Geotags (Admin Only)</h4>
            <p class="page-subtitle">Shows location metadata for captured leads. Client details remain hidden.</p>
            ${renderLeadGeotagsForAdmin(name)}
        </div>
        ` : ''}
        <div class="insight-card">
            <h4>Archive JFA</h4>
            <p class="page-subtitle">Use when a JFA has left the team. This performs a soft-delete (archive).</p>
            <div class="menu-page-actions">
                <button class="action-btn secondary" type="button" onclick="deleteJfaAdmin('${escapeHtml(name)}')">Delete JFA</button>
            </div>
        </div>
    `;
    activeInlineDetail[source] = normalized;
    highlightInlineSelection(source);
    bodyEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeAdminJfaModal() {
    const modal = document.getElementById('admin-jfa-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
}

function openLeadSignaturePreview(encodedId) {
    if (adminRole !== 'ADMIN') {
        showToast('Only Admin (All) can view client signatures.', 'error');
        return;
    }
    const id = decodeURIComponent(encodedId || '');
    const lead = leadRecords.find((item) => String(item.id) === id);
    if (!lead || !lead.clientSignatureImage) {
        showToast('Signature not found for this lead.', 'error');
        return;
    }
    const modal = document.getElementById('lead-signature-modal');
    const image = document.getElementById('leadSignaturePreviewImage');
    const meta = document.getElementById('leadSignaturePreviewMeta');
    if (!modal || !(image instanceof HTMLImageElement) || !meta) return;
    image.src = lead.clientSignatureImage;
    image.alt = `Client signature for ${formatJfaName(lead.jfaName || 'JFA')}`;
    const when = lead.timestamp ? new Date(lead.timestamp).toLocaleString('en-ZA') : '—';
    meta.textContent = `LID ${lead.leadId || '—'} • ${formatJfaName(lead.jfaName || 'JFA')} • ${when}`;
    logAudit('Viewed client signature', `LID ${lead.leadId || '—'} • ${formatJfaName(lead.jfaName || 'JFA')}`);
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeLeadSignaturePreview() {
    const modal = document.getElementById('lead-signature-modal');
    const image = document.getElementById('leadSignaturePreviewImage');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    if (image instanceof HTMLImageElement) image.src = '';
}

function confirmConsentForms(name, inputId = 'adminConfirmFormsAdmin', source = 'admin') {
    if (adminRole === 'PERSONAL') {
        showToast('Only team leaders or admin can verify forms.', 'error');
        return;
    }
    const input = document.getElementById(inputId);
    if (!input) return;
    const newValue = Math.max(0, parseInt(input.value || '0', 10));
    const normalized = normalizeJfaName(name);
    const today = todayKey();
    let todayRecords = jfaRecords.filter((r) => normalizeJfaName(r.name) === normalized && recordDateKey(r) === today);
    if (adminRole === 'TEAM' && adminTeam) {
        todayRecords = todayRecords.filter((record) => record.team === adminTeam);
    }
    if (!todayRecords.length) {
        showToast('No records found for today.', 'error');
        return;
    }
    const digitalAutoCount = getTodayLeadCountForName(name);
    if (newValue < digitalAutoCount) {
        showToast(`Final total cannot be lower than digital leads (${digitalAutoCount}).`, 'error');
        input.value = String(Math.max(digitalAutoCount, 0));
        return;
    }
    const currentTotal = todayRecords.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const delta = newValue - currentTotal;
    const physicalForms = Math.max(0, newValue - digitalAutoCount);
    todayRecords.forEach((record, index) => {
        if (index === 0) {
            record.leadAutoCount = digitalAutoCount;
            record.physicalConsentForms = physicalForms;
            record.manualConsentAdjustment = physicalForms;
            record.consentForms = newValue;
        } else {
            record.leadAutoCount = 0;
            record.physicalConsentForms = 0;
            record.manualConsentAdjustment = 0;
            record.consentForms = 0;
        }
    });
    if (todayRecords[0]?.facility?.id) {
        const facility = getFacilityById(todayRecords[0].facility.id);
        if (facility) {
            facility.consentForms = Math.max(0, (facility.consentForms || 0) + delta);
            saveFacilityStats();
        }
    }
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    logAudit('Verified consent forms', `${formatJfaName(name)}: total ${newValue} (physical ${physicalForms} + digital ${digitalAutoCount})`);
    showToast(`Final total confirmed: ${newValue} (physical ${physicalForms} + digital ${digitalAutoCount}).`, 'success');
    renderAdminTeamDetails();
    if (source === 'team') {
        openAdminJfaDetail(name, 'team', true);
    } else {
        openAdminJfaDetail(name, 'admin', true);
    }
    updateStatistics();
    updateSummary();
}

function highlightInlineSelection(source) {
    const selected = activeInlineDetail[source];
    const cards = document.querySelectorAll(`.admin-jfa-card[data-source="${source}"]`);
    cards.forEach((card) => {
        const name = normalizeJfaName(card.getAttribute('data-name') || '');
        card.classList.toggle('is-selected', Boolean(selected) && name === selected);
    });
}

async function deleteJfaAdmin(name) {
    if (adminRole === 'PERSONAL') {
        showToast('Only team leaders/admins can delete a JFA.', 'error');
        return;
    }
    const normalized = normalizeJfaName(name);
    const candidate = jfaRecords.find((r) => normalizeJfaName(r.name) === normalized);
    if (!candidate) {
        showToast('JFA not found.', 'error');
        return;
    }
    if (adminRole === 'TEAM' && candidate.team !== adminTeam) {
        showToast('You can only delete JFAs from your team.', 'error');
        return;
    }
    const confirmed = await openAppConfirmModal({
        title: 'Archive JFA?',
        message: `Archive ${formatJfaName(name)}? This hides the JFA from active lists and leaderboards.`,
        confirmText: 'Archive',
        cancelText: 'Cancel'
    });
    if (!confirmed) {
        showToast('Archive cancelled.', 'error');
        return;
    }

    archiveJfaName(name);
    jfaRecords = jfaRecords.map((r) => {
        if (normalizeJfaName(r.name) !== normalized) return r;
        return { ...r, archived: true };
    });

    const archives = getArchives();
    archives.forEach((archive) => {
        archive.records = (archive.records || []).map((r) => {
            if (normalizeJfaName(r.name) !== normalized) return r;
            return { ...r, archived: true };
        });
    });

    if (currentJFA && normalizeJfaName(currentJFA.name) === normalized) {
        currentJFA = null;
        localStorage.removeItem(STORAGE_KEYS.currentJfa);
    }

    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(archives));
    logAudit('Archived JFA', `${formatJfaName(name)} archived by ${adminRole}`);
    showToast('JFA archived (soft delete).', 'success');
    closeAdminJfaModal();
    renderAdminInsights();
    renderAdminTeamDetails();
    updateStatistics();
    updateSummary();
}

function resetAllStats() {
    if (adminRole !== 'ADMIN') {
        showToast('Only the main admin can reset all stats.', 'error');
        return;
    }
    openResetStatsConfirmModal();
}

function openResetStatsConfirmModal() {
    const modal = document.getElementById('reset-stats-confirm-modal');
    const input = document.getElementById('resetStatsConfirmInput');
    const error = document.getElementById('resetStatsConfirmError');
    if (!modal) return;
    if (input) input.value = '';
    if (error) {
        error.textContent = '';
        error.style.display = 'none';
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    if (input) setTimeout(() => input.focus(), 30);
}

function closeResetStatsConfirmModal() {
    const modal = document.getElementById('reset-stats-confirm-modal');
    const error = document.getElementById('resetStatsConfirmError');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    if (error) {
        error.textContent = '';
        error.style.display = 'none';
    }
}

function confirmResetAllStatsFromModal() {
    const input = document.getElementById('resetStatsConfirmInput');
    const error = document.getElementById('resetStatsConfirmError');
    if ((input?.value || '').trim() !== 'RESET STATS') {
        if (error) {
            error.textContent = 'Type RESET STATS exactly to continue.';
            error.style.display = 'block';
        }
        return;
    }
    closeResetStatsConfirmModal();
    jfaRecords.forEach((record) => {
        record.consentForms = 0;
    });
    const archives = getArchives();
    archives.forEach((archive) => {
        (archive.records || []).forEach((record) => {
            record.consentForms = 0;
        });
    });
    facilities.forEach((facility) => {
        facility.consentForms = 0;
    });
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(archives));
    saveFacilityStats();
    logAudit('Reset all stats', 'Admin reset all consent form totals.');
    showToast('All stats reset to 0.', 'success');
    renderAdminTeamDetails();
    updateStatistics();
    updateSummary();
}

function resetAllData() {
    if (adminRole !== 'ADMIN') {
        showToast('Only the main admin can reset all data.', 'error');
        return;
    }

    jfaRecords = [];
    currentJFA = null;
    preAssignedFacilityId = null;
    facilityRenderLimit = FACILITY_PAGE_SIZE;

    facilities.forEach((facility) => {
        facility.allocations = 0;
        facility.consentForms = 0;
        facility.visits = [];
    });

    localStorage.removeItem(STORAGE_KEYS.records);
    localStorage.removeItem(STORAGE_KEYS.archives);
    localStorage.removeItem(STORAGE_KEYS.facilities);
    localStorage.removeItem(STORAGE_KEYS.customFacilities);
    localStorage.removeItem(STORAGE_KEYS.lastReset);
    localStorage.removeItem(STORAGE_KEYS.dbdDraft);
    localStorage.removeItem(STORAGE_KEYS.lastDbd);
    localStorage.removeItem(STORAGE_KEYS.currentJfa);
    localStorage.removeItem(STORAGE_KEYS.lastPage);
    localStorage.removeItem(STORAGE_KEYS.auditLog);
    localStorage.removeItem(STORAGE_KEYS.archivedJfas);
    localStorage.removeItem(STORAGE_KEYS.weeklyFeedback);
    localStorage.removeItem(STORAGE_KEYS.weeklyFeedbackArchive);
    localStorage.removeItem(STORAGE_KEYS.weeklyKey);
    localStorage.removeItem(STORAGE_KEYS.facilityDirectory);
    localStorage.removeItem(STORAGE_KEYS.leads);
    localStorage.removeItem(STORAGE_KEYS.lastJfaIdentity);
    localStorage.removeItem(STORAGE_KEYS.jfaProfiles);
    localStorage.removeItem(STORAGE_KEYS.faProfiles);
    localStorage.removeItem(STORAGE_KEYS.formsLibrary);
    localStorage.removeItem(STORAGE_KEYS.learningOverrides);
    localStorage.removeItem(STORAGE_KEYS.interventions);
    localStorage.removeItem(STORAGE_KEYS.learningQuizRecent);
    localStorage.removeItem(STORAGE_KEYS.adminPassword);
    localStorage.removeItem(STORAGE_KEYS.userAccounts);
    localStorage.removeItem(STORAGE_KEYS.userMgmtAudit);
    localStorage.removeItem(STORAGE_KEYS.leadDraft);
    localStorage.removeItem(STORAGE_KEYS.registerDraft);
    localStorage.removeItem(STORAGE_KEYS.appointments);
    localStorage.removeItem('learningBookmark');
    localStorage.removeItem('lastLearningKey');
    localStorage.removeItem('adminRole');
    localStorage.removeItem('adminTeam');
    sessionStorage.removeItem(SESSION_KEYS.adminRole);
    sessionStorage.removeItem(SESSION_KEYS.adminTeam);
    sessionStorage.removeItem(SESSION_KEYS.adminAccess);
    adminRole = 'PERSONAL';
    adminTeam = '';
    archivedJfaNames = new Set();
    leadRecords = [];
    appointmentRecords = [];
    jfaProfiles = {};
    faProfiles = {};
    learningOverrides = {};
    interventionLog = {};
    learningQuizRecent = {};
    formsLibrary = getDefaultFormsLibrary();
    appUser = '';
    settingsUserFilter = '';
    sessionStorage.removeItem(SESSION_KEYS.appUser);
    ensureDefaultUserAccount();
    ensureDefaultTeamLeaderAccounts();

    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    scheduleStorageWrite(STORAGE_KEYS.facilities, JSON.stringify({}));
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify([]));
    scheduleStorageWrite(STORAGE_KEYS.formsLibrary, JSON.stringify(formsLibrary));
    scheduleStorageWrite(STORAGE_KEYS.learningOverrides, JSON.stringify(learningOverrides));
    scheduleStorageWrite(STORAGE_KEYS.interventions, JSON.stringify(interventionLog));
    scheduleStorageWrite(STORAGE_KEYS.learningQuizRecent, JSON.stringify(learningQuizRecent));
    scheduleStorageWrite(STORAGE_KEYS.faProfiles, JSON.stringify(faProfiles));

    logAudit('Reset ALL data', 'Admin cleared all records, archives, and facilities.');
    showToast('All data reset.', 'success');

    populateFacilityDropdown();
    updateSummary();
    updateStatistics();
    renderArchives();
    renderAdminInsights();
    renderAdminTeamDetails();
    renderFormsLibrary();
    updateResumeBanner();
    updateAppUserBadge();
    setAuthMode('signin');
    lockAppToAuth();
    goToPage('landing-page');
}

function openArchivedJfas() {
    if (adminRole === 'PERSONAL') {
        showToast('Only team leaders/admins can view archived JFAs.', 'error');
        return;
    }
    openMenuPage('archivedJfas');
}

function renderArchivedJfas() {
    const list = document.getElementById('archivedJfaList');
    if (!list) return;
    const archived = [...archivedJfaNames];
    if (!archived.length) {
        list.innerHTML = '<p class="menu-page-note">No archived JFAs.</p>';
        return;
    }
    const search = (document.getElementById('archivedJfaSearch')?.value || '').trim().toLowerCase();
    const display = archived.map((name) => formatJfaName(name)).sort();
    const filtered = search
        ? display.filter((name) => name.toLowerCase().includes(search))
        : display;
    if (!filtered.length) {
        list.innerHTML = '<p class="menu-page-note">No matches found.</p>';
        return;
    }
    list.innerHTML = filtered.map((name) => `
        <div class="admin-jfa-card">
            <div>
                <strong>${name}</strong>
                <div class="page-subtitle">Archived</div>
            </div>
            <button class="action-btn secondary restore-btn" type="button" onclick="restoreArchivedJfa('${escapeHtml(name)}')">Restore</button>
        </div>
    `).join('');
}

function filterArchivedJfas() {
    renderArchivedJfas();
}

function clearArchivedSearch() {
    const input = document.getElementById('archivedJfaSearch');
    if (input) input.value = '';
    renderArchivedJfas();
}
function restoreArchivedJfa(name) {
    if (adminRole === 'PERSONAL') {
        showToast('Only team leaders/admins can restore a JFA.', 'error');
        return;
    }
    const normalized = normalizeJfaName(name);
    if (!archivedJfaNames.has(normalized)) {
        showToast('JFA is not archived.', 'error');
        return;
    }
    archivedJfaNames.delete(normalized);
    scheduleStorageWrite(STORAGE_KEYS.archivedJfas, JSON.stringify([...archivedJfaNames]));
    jfaRecords = jfaRecords.map((r) => {
        if (normalizeJfaName(r.name) !== normalized) return r;
        const { archived, ...rest } = r;
        return rest;
    });
    const archives = getArchives();
    archives.forEach((archive) => {
        archive.records = (archive.records || []).map((r) => {
            if (normalizeJfaName(r.name) !== normalized) return r;
            const { archived, ...rest } = r;
            return rest;
        });
    });
    scheduleStorageWrite(STORAGE_KEYS.records, JSON.stringify(jfaRecords));
    scheduleStorageWrite(STORAGE_KEYS.archives, JSON.stringify(archives));
    logAudit('Restored JFA', `${formatJfaName(name)} restored by ${adminRole}`);
    showToast('JFA restored.', 'success');
    renderArchivedJfas();
    renderAdminInsights();
    renderAdminTeamDetails();
    updateStatistics();
    updateSummary();
}

function buildLearningPages(text) {
    const blocks = text.split(/\n\s*\n/).map((block) => block.trim()).filter(Boolean);
    const pages = [];
    let current = [];
    blocks.forEach((block) => {
        current.push(block);
        if (current.length >= 4) {
            pages.push(current);
            current = [];
        }
    });
    if (current.length) pages.push(current);
    return pages.length ? pages : [blocks];
}

const learningAnchorIndex = {};

function buildLearningAnchorIndex(key, pages) {
    const index = {};
    pages.forEach((page, pageIndex) => {
        const text = page.join('\n\n');
        const matches = [...text.matchAll(/id="([^"]+)"/g)];
        matches.forEach((match) => {
            const anchor = match[1];
            if (!anchor) return;
            if (index[anchor] == null) {
                index[anchor] = pageIndex;
            }
        });
    });
    learningAnchorIndex[key] = index;
    return index;
}

function formatLearningText(text) {
    return String(text || '')
        .replace(/<a href="#([^"]+)">/g, '<a href="#$1" class="learning-anchor" data-anchor="$1">')
        .replace(/\[Back to top\]\(#jfa-top\)/g, '<a href="#jfa-top" class="learning-top-link">Back to top</a>')
        .replace(/\n/g, '<br>');
}

function renderLearningPage(key, pages) {
    const learningBody = document.getElementById('learningBody');
    const productBody = document.getElementById('productBody');
    if (!learningBody || !productBody) return;
    const pageIndex = Math.min(Math.max(learningPageState[key] || 0, 0), pages.length - 1);
    learningPageState[key] = pageIndex;
    buildLearningAnchorIndex(key, pages);
    let html = formatLearningText(pages[pageIndex].join('\n\n'));
    if (learningSearchTerm) {
        const safeTerm = escapeRegExp(learningSearchTerm);
        const regex = new RegExp(safeTerm, 'gi');
        html = html.replace(regex, (match) => `<mark class="learning-mark">${match}</mark>`);
    }
    const controls = `
        <div class="learning-pagination">
            <button class="action-btn secondary" type="button" onclick="changeLearningPage('${key}', -1)" ${pageIndex === 0 ? 'disabled' : ''}>Prev</button>
            <span class="learning-page-indicator">Page ${pageIndex + 1} of ${pages.length}</span>
            <button class="action-btn secondary" type="button" onclick="changeLearningPage('${key}', 1)" ${pageIndex >= pages.length - 1 ? 'disabled' : ''}>Next</button>
        </div>
    `;
    const output = `${renderLearningTopicLogo(key, true)}${html}${controls}`;
    if (['consolidation', 'life', 'capital', 'matla'].includes(key)) {
        productBody.innerHTML = output;
        learningBody.innerHTML = '';
        productBody.dataset.learningKey = key;
    } else {
        learningBody.innerHTML = output;
        productBody.innerHTML = '';
        learningBody.dataset.learningKey = key;
    }
}

function renderLearningTopicLogo(key, compact = false) {
    if (key !== 'consolidation' && key !== 'capital') return '';
    const isCapital = key === 'capital';
    const src = isCapital ? 'Capital-Legacy.png' : 'RMA.png';
    const alt = isCapital ? 'Capital Legacy logo' : 'RMA logo';
    const title = isCapital ? 'Capital Legacy Wills & Estates' : 'RMA Consolidated Funeral Product';
    const subtitle = isCapital ? 'Official estate planning module' : 'Official product knowledge module';
    return `
        <div class="learning-topic-logo${compact ? ' compact' : ''}">
            <img src="${src}" alt="${alt}">
            <div class="learning-topic-logo-copy">
                <strong>${title}</strong>
                <span>${subtitle}</span>
            </div>
        </div>
    `;
}

function changeLearningPage(key, delta) {
    const text = getLearningContent(key);
    if (!text) return;
    const pages = buildLearningPages(text);
    const current = learningPageState[key] || 0;
    const next = Math.min(Math.max(current + delta, 0), pages.length - 1);
    learningPageState[key] = next;
    renderLearningPage(key, pages);
}

function resumeLearning() {
    const key = localStorage.getItem('lastLearningKey');
    if (!key) return;
    showLearning(key);
    const body = document.getElementById('learningBody');
    if (body) body.scrollIntoView({ behavior: 'smooth' });
}

function updateLearningResumeButton() {
    const btn = document.getElementById('learningResumeBtn');
    if (!btn) return;
    const key = localStorage.getItem('lastLearningKey');
    if (!key) {
        btn.style.display = 'none';
        return;
    }
    btn.textContent = `Resume: ${getLearningTitle(key)}`;
    btn.style.display = 'inline-flex';
}

function applyLearningSearch() {
    const input = document.getElementById('learningSearchInput');
    if (!input) return;
    learningSearchTerm = input.value.trim();
    renderLearningSearchResults();
    const key = localStorage.getItem('lastLearningKey');
    if (!key) return;
    showLearning(key);
    const body = document.getElementById('learningBody');
    if (body) body.scrollIntoView({ behavior: 'smooth' });
}

function clearLearningSearch() {
    learningSearchTerm = '';
    const input = document.getElementById('learningSearchInput');
    if (input) input.value = '';
    renderLearningSearchResults();
    const key = localStorage.getItem('lastLearningKey');
    if (!key) return;
    showLearning(key);
}

function saveLearningBookmark() {
    const key = localStorage.getItem('lastLearningKey');
    if (!key) return;
    const page = learningPageState[key] || 0;
    localStorage.setItem('learningBookmark', JSON.stringify({ key, page }));
    showToast('Bookmark saved.', 'success');
    updateLearningBookmarkButton();
}

function openLearningBookmark() {
    const raw = localStorage.getItem('learningBookmark');
    if (!raw) {
        showToast('No bookmark saved yet.', 'error');
        return;
    }
    const { key, page } = JSON.parse(raw);
    if (!key) return;
    learningPageState[key] = page || 0;
    showLearning(key);
    showToast('Opened bookmark.', 'success');
}

function updateLearningBookmarkButton() {
    const bookmarkBtn = document.getElementById('learningBookmarkBtn');
    const openBtn = document.getElementById('learningOpenBookmarkBtn');
    const key = localStorage.getItem('lastLearningKey');
    if (bookmarkBtn) {
        bookmarkBtn.style.display = key ? 'inline-flex' : 'none';
    }
    const hasBookmark = Boolean(localStorage.getItem('learningBookmark'));
    if (openBtn) {
        openBtn.style.display = hasBookmark ? 'inline-flex' : 'none';
    }
}

function openLearningDetail(key) {
    const titleEl = document.getElementById('learningDetailTitle');
    const bodyEl = document.getElementById('learningDetailBody');
    if (!titleEl || !bodyEl) return;
    const text = getLearningContent(key) || 'Content coming soon.';
    const pages = buildLearningPages(text);
    const pageIndex = learningPageState[key] || 0;
    const title = getLearningTitle(key);
    buildLearningAnchorIndex(key, pages);
    titleEl.textContent = title;
    bodyEl.innerHTML = `
        <div class="learning-panel">
            ${renderLearningTopicLogo(key)}
            <h4>Lesson</h4>
            <div>${formatLearningText(pages[pageIndex].join('\n\n'))}</div>
        </div>
        <div class="learning-panel learning-checklist">
            <h4>Quick Actions</h4>
            <label><input type="checkbox" class="learning-action"> Summarize the key idea in one sentence</label>
            <label><input type="checkbox" class="learning-action"> Practice the example with your own words</label>
            <label><input type="checkbox" class="learning-action"> Identify one improvement for today</label>
        </div>
        <div class="learning-panel learning-quiz">
            <h4>Check Your Understanding</h4>
            ${renderLearningQuiz(key)}
        </div>
        <div class="learning-panel learning-reflection">
            <h4>Reflection</h4>
            <textarea id="learningReflection" placeholder="Write your key takeaway, one blocker, and your next action..."></textarea>
            <button class="action-btn" type="button" onclick="saveLearningReflection('${key}')">Save Reflection</button>
        </div>
        <div class="learning-panel">
            <div class="learning-pagination">
                <button class="action-btn secondary" type="button" onclick="changeLearningPage('${key}', -1); openLearningDetail('${key}');" ${pageIndex === 0 ? 'disabled' : ''}>Prev</button>
                <span class="learning-page-indicator">Page ${pageIndex + 1} of ${pages.length}</span>
                <button class="action-btn secondary" type="button" onclick="changeLearningPage('${key}', 1); openLearningDetail('${key}');" ${pageIndex >= pages.length - 1 ? 'disabled' : ''}>Next</button>
            </div>
        </div>
    `;
    const saved = localStorage.getItem(`learningReflection:${key}`);
    if (saved) {
        const textarea = document.getElementById('learningReflection');
        if (textarea) textarea.value = saved;
    }
    const actions = document.querySelectorAll('.learning-action');
    actions.forEach((action) => {
        action.addEventListener('change', updateLearningDetailProgress);
    });
    const reflection = document.getElementById('learningReflection');
    if (reflection) {
        reflection.addEventListener('input', updateLearningDetailProgress);
    }
    updateLearningDetailProgress();
    bodyEl.dataset.learningKey = key;
    openMenuPage('learningDetail');
}

const LEARNING_QUIZ_BANK = {
    jfaManual: [
        { id: 'jfa-1', q: 'The Consolidated Funeral Plan is primarily a:', a: 'Replacement product', options: ['New policy add-on', 'Replacement product', 'Savings account'] },
        { id: 'jfa-2', q: 'What is the affordability cap for government employees?', a: '15% of basic salary', options: ['10% of basic salary', '15% of basic salary', '20% of basic salary'] },
        { id: 'jfa-3', q: 'Which documents are required as supporting documents?', a: 'ID and recent payslip', options: ['ID and bank statement', 'ID and recent payslip', 'Passport only'] },
        { id: 'jfa-4', q: 'What is the purpose of cancellations in this process?', a: 'Prevent double debits', options: ['Increase premiums', 'Prevent double debits', 'Avoid quotations'] }
    ],
    marketing: [
        { id: 'marketing-1', q: 'What is the first gear of a marketing system?', a: 'Awareness', options: ['Retention', 'Awareness', 'Decision'] },
        { id: 'marketing-2', q: 'Why does a system beat random effort?', a: 'Predictability', options: ['Luck', 'Predictability', 'Speed'] },
        { id: 'marketing-3', q: 'The main goal of a marketing funnel is to create:', a: 'Consistent conversion flow', options: ['Viral luck', 'Consistent conversion flow', 'One-time hype'] },
        { id: 'marketing-4', q: 'What should happen after a first client conversation?', a: 'Clear next step', options: ['Wait for callback only', 'Clear next step', 'Start from scratch'] },
        { id: 'marketing-5', q: 'Daily tracking in marketing helps with:', a: 'Performance correction', options: ['Avoiding accountability', 'Performance correction', 'More paperwork only'] }
    ],
    loa: [
        { id: 'loa-1', q: 'Law of Averages teaches:', a: 'Consistency', options: ['Consistency', 'Shortcuts', 'Luck'] },
        { id: 'loa-2', q: 'Over 100 conversations, a 1:10 ratio gives:', a: '10 sales', options: ['1 sale', '10 sales', '50 sales'] },
        { id: 'loa-3', q: 'If outcomes feel low, LOA says to improve mainly by:', a: 'Increasing quality and quantity of attempts', options: ['Waiting for better weather', 'Increasing quality and quantity of attempts', 'Changing product daily'] },
        { id: 'loa-4', q: 'LOA reduces emotional swings because it focuses on:', a: 'Process over one result', options: ['One lucky close', 'Process over one result', 'Perfect timing'] },
        { id: 'loa-5', q: 'A core LOA habit is:', a: 'Daily discipline', options: ['Daily discipline', 'Random bursts', 'Only month-end push'] }
    ],
    five: [
        { id: 'five-1', q: 'Step 4 is:', a: 'Close', options: ['Presentation', 'Close', 'Rehash'] },
        { id: 'five-2', q: 'Before closing, a rep should confirm:', a: 'Client understanding and need', options: ['Only budget', 'Client understanding and need', 'Team ranking'] },
        { id: 'five-3', q: 'A strong 5-step flow mainly improves:', a: 'Consistency in delivery', options: ['Script memorization only', 'Consistency in delivery', 'Random improvisation'] },
        { id: 'five-4', q: 'If the close fails, the next best step is to:', a: 'Re-check needs and objections', options: ['End the interaction', 'Re-check needs and objections', 'Skip follow-up'] }
    ],
    eight: [
        { id: 'eight-1', q: 'Step 1 in 8 Steps is:', a: 'Identify Your Target Market', options: ['Capture Leads', 'Identify Your Target Market', 'Craft Message'] },
        { id: 'eight-2', q: 'An 8-step system helps teams by improving:', a: 'Repeatable execution', options: ['Luck', 'Repeatable execution', 'Guesswork'] },
        { id: 'eight-3', q: 'If one step is skipped often, the likely result is:', a: 'Lower conversion consistency', options: ['Automatic recovery', 'Lower conversion consistency', 'Higher certainty'] },
        { id: 'eight-4', q: 'The value of an 8-step framework is strongest when it is:', a: 'Used consistently by the team', options: ['Changed daily', 'Used consistently by the team', 'Only used by top performers'] }
    ],
    fugi: [
        { id: 'fugi-1', q: 'FUGI stands for:', a: 'Fear, Urgency, Greed, Indifference', options: ['Fear, Urgency, Greed, Indifference', 'Focus, Use, Grow, Improve'] },
        { id: 'fugi-2', q: 'FUGI factors are mainly used to:', a: 'Understand buying behavior', options: ['Set commission rates', 'Understand buying behavior', 'Replace compliance'] },
        { id: 'fugi-3', q: 'Ignoring FUGI signals usually hurts:', a: 'Relevance of your pitch', options: ['Product range', 'Relevance of your pitch', 'Office logistics'] },
        { id: 'fugi-4', q: 'A FUGI-aware conversation should adapt to:', a: 'The client’s real motivators', options: ['The script only', 'The client’s real motivators', 'The fastest close'] }
    ],
    impulse: [
        { id: 'impulse-1', q: 'IMPULSE includes:', a: 'Immediacy', options: ['Immediacy', 'Scarcity', 'Risk'] },
        { id: 'impulse-2', q: 'Impulse buying is best handled with:', a: 'Ethical urgency and clarity', options: ['Pressure without facts', 'Ethical urgency and clarity', 'No follow-up'] },
        { id: 'impulse-3', q: 'To avoid regret-driven cancellations, you should:', a: 'Set clear expectations before close', options: ['Skip details', 'Set clear expectations before close', 'Delay all disclosures'] },
        { id: 'impulse-4', q: 'An ethical urgency message should always include:', a: 'Accurate product context', options: ['Hidden terms', 'Accurate product context', 'No affordability check'] }
    ],
    cod: [
        { id: 'cod-1', q: 'What is the purpose of promoting tools?', a: 'Promote the expansion and opportunity', options: ['Promote the expansion and opportunity', 'Replace training', 'Skip goals'] },
        { id: 'cod-2', q: 'In the field, how often should you meet a confident R/O?', a: 'Every +/- 2 hours', options: ['Every +/- 2 hours', 'Every 30 minutes', 'Only at the end'] },
        { id: 'cod-3', q: 'Cycle Of Development is strongest when teams focus on:', a: 'Continuous coaching and application', options: ['One-off training', 'Continuous coaching and application', 'Only monthly audits'] },
        { id: 'cod-4', q: 'COD momentum is usually lost when teams:', a: 'Stop follow-through and coaching', options: ['Track progress daily', 'Stop follow-through and coaching', 'Share field feedback'] }
    ],
    cross: [
        { id: 'cross-1', q: 'Cross-selling means:', a: 'Using multiple products to meet client needs', options: ['Using one product only', 'Using multiple products to meet client needs', 'Selling only to existing clients'] },
        { id: 'cross-2', q: 'When should cross-selling happen?', a: 'During all consultations and service follow-ups', options: ['Only when client asks', 'During all consultations and service follow-ups', 'Only during onboarding'] },
        { id: 'cross-3', q: 'A key requirement before cross-selling is:', a: 'Product training and needs analysis', options: ['Price discounting', 'Product training and needs analysis', 'Skipping verification'] },
        { id: 'cross-4', q: 'Cross-selling should never ignore:', a: 'Client suitability and affordability', options: ['Daily targets', 'Client suitability and affordability', 'Team competition'] }
    ],
    matla: [
        { id: 'matla-1', q: 'Can family benefit be sold without policyholder cover?', a: 'No', options: ['Yes', 'No', 'Only with manager approval'] },
        { id: 'matla-2', q: 'What must be explained when system flags existing policy?', a: 'Possible second deduction', options: ['Only policy number', 'Possible second deduction', 'Nothing, system handles it'] },
        { id: 'matla-3', q: 'Policy can be issued at submission when:', a: 'Affordability passes', options: ['Signature is clear', 'Affordability passes', 'Beneficiary is added'] },
        { id: 'matla-4', q: 'A compliant Matla sale requires:', a: 'Clear benefit explanation and consent', options: ['Fast signature only', 'Clear benefit explanation and consent', 'No affordability checks'] }
    ],
    consolidation: [
        { id: 'consolidation-1', q: 'Maximum cover for Main Member is:', a: 'R100 000', options: ['R50 000', 'R70 000', 'R100 000'] },
        { id: 'consolidation-2', q: 'Natural death waiting period is:', a: '6 months', options: ['No waiting period', '6 months', '12 months'] },
        { id: 'consolidation-3', q: 'Initial distribution channel is:', a: 'Matla Life', options: ['RMA Admin Services', 'Matla Life', 'EuropAssist'] },
        { id: 'consolidation-4', q: 'Consolidation discussions should start with:', a: 'Needs and affordability review', options: ['Immediate policy replacement', 'Needs and affordability review', 'Competitor criticism'] }
    ]
};

function shuffleArray(list) {
    const arr = [...list];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function pickLearningQuizQuestions(key, count = 3) {
    const pool = LEARNING_QUIZ_BANK[key] || [];
    if (!pool.length) return [];
    const maxPick = Math.min(count, pool.length);
    const recent = Array.isArray(learningQuizRecent[key]) ? learningQuizRecent[key] : [];
    const fresh = pool.filter((item) => !recent.includes(item.id));
    const picked = shuffleArray(fresh).slice(0, maxPick);
    if (picked.length < maxPick) {
        const remainder = pool.filter((item) => !picked.some((sel) => sel.id === item.id));
        picked.push(...shuffleArray(remainder).slice(0, maxPick - picked.length));
    }
    const recentLimit = Math.min(pool.length, Math.max(5, maxPick * 2));
    learningQuizRecent[key] = [
        ...picked.map((item) => item.id),
        ...recent.filter((id) => !picked.some((item) => item.id === id))
    ].slice(0, recentLimit);
    scheduleStorageWrite(STORAGE_KEYS.learningQuizRecent, JSON.stringify(learningQuizRecent));
    learningQuizState[key] = picked;
    return picked;
}

function getLearningQuizQuestionCount(key) {
    const size = (LEARNING_QUIZ_BANK[key] || []).length;
    if (size <= 2) return size;
    if (size === 3) return 2;
    return 3;
}

function renderLearningQuiz(key) {
    const set = pickLearningQuizQuestions(key, getLearningQuizQuestionCount(key));
    if (!set.length) return '<p class="page-subtitle">Quiz coming soon.</p>';
    return set.map((item, idx) => {
        const options = shuffleArray(item.options || []);
        const buttons = options
            .map((opt) => `<button class="action-btn secondary" type="button" onclick="answerLearningQuiz('${key}', ${idx}, '${encodeURIComponent(opt)}')">${escapeHtml(opt)}</button>`)
            .join('');
        return `<div><p><strong>${escapeHtml(item.q)}</strong></p><div class="menu-page-actions">${buttons}</div><div id="quiz-feedback-${key}-${idx}" class="page-subtitle"></div></div>`;
    }).join('');
}

function answerLearningQuiz(key, index, answerEncoded) {
    const set = learningQuizState[key] || [];
    const correct = set[index]?.a;
    const answer = decodeURIComponent(answerEncoded || '');
    const feedback = document.getElementById(`quiz-feedback-${key}-${index}`);
    if (!feedback || !correct) return;
    if (answer === correct) {
        feedback.textContent = 'Correct!';
        feedback.style.color = '#1E8449';
    } else {
        feedback.textContent = `Not quite. Correct: ${correct}`;
        feedback.style.color = '#C0392B';
    }
    updateLearningDetailProgress();
}

function saveLearningReflection(key) {
    const textarea = document.getElementById('learningReflection');
    if (!textarea) return;
    const content = textarea.value.trim();
    if (!content) {
        showToast('Write a short reflection first.', 'error');
        return;
    }
    localStorage.setItem(`learningReflection:${key}`, content);
    showToast('Reflection saved.', 'success');
    updateLearningDetailProgress();
}

function updateLearningDetailProgress() {
    const fill = document.getElementById('learningDetailFill');
    const label = document.getElementById('learningDetailProgressLabel');
    if (!fill || !label) return;
    const checked = document.querySelectorAll('.learning-action:checked').length;
    const totalActions = document.querySelectorAll('.learning-action').length || 3;
    const reflection = document.getElementById('learningReflection')?.value?.trim() ? 1 : 0;
    const progress = Math.min(100, Math.round(((checked + reflection) / (totalActions + 1)) * 100));
    fill.style.width = `${progress}%`;
    label.textContent = `Progress: ${progress}%`;
}

function jumpToLearningAnchor(anchor, container = null) {
    const key = container?.dataset?.learningKey || localStorage.getItem('lastLearningKey');
    if (!key || !anchor) return;
    const text = getLearningContent(key) || '';
    const pages = buildLearningPages(text);
    const index = learningAnchorIndex[key] || buildLearningAnchorIndex(key, pages);
    const targetPage = index[anchor] != null ? index[anchor] : (anchor === 'jfa-top' ? 0 : null);
    if (targetPage == null) {
        showToast('Topic section not found on this page.', 'error');
        return;
    }
    learningPageState[key] = targetPage;
    const openPage = getOpenMenuPage()?.id || '';
    if (openPage === 'learningDetailPage') {
        openLearningDetail(key);
    } else {
        showLearning(key);
    }
    setTimeout(() => {
        const target = document.getElementById(anchor);
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }, 60);
}

function bindLearningAnchorHandlers() {
    const containers = [
        document.getElementById('learningBody'),
        document.getElementById('productBody'),
        document.getElementById('learningDetailBody')
    ].filter(Boolean);
    containers.forEach((container) => {
        container.addEventListener('click', (event) => {
            const link = event.target.closest('a.learning-anchor, a.learning-top-link');
            if (!link) return;
            const anchor = link.getAttribute('data-anchor') || link.getAttribute('href')?.replace('#', '');
            if (!anchor) return;
            event.preventDefault();
            jumpToLearningAnchor(anchor, container);
        });
    });
}
function getLearningTitle(key) {
    const map = {
        jfaManual: 'JFA Manual (Day 1)',
        marketing: 'Marketing System',
        loa: 'L.O.A. (Law of Average)',
        five: '5 Steps',
        eight: '8 Steps',
        fugi: 'FUGI Factors',
        impulse: 'Impulse Factors',
        cod: 'C.O.D. (Cycle Of Development)',
        cross: 'Cross Selling',
        consolidation: 'Consolidation',
        capital: 'Capital Legacy',
        life: 'Life Cover',
        matla: 'Matla Plan'
    };
    return map[key] || 'Learning';
}

function renderLearningSearchResults() {
    const container = document.getElementById('learningSearchResults');
    if (!container) return;
    if (!learningSearchTerm) {
        container.innerHTML = '';
        return;
    }
    const results = searchLearningAll(learningSearchTerm);
    if (!results.length) {
        container.innerHTML = '<div class="learning-search-item"><strong>No results</strong><span>Try a different keyword.</span></div>';
        return;
    }
    container.innerHTML = results
        .map((result) => {
            const title = getLearningTitle(result.key);
            const snippet = result.snippet.replace(/\n/g, ' ').trim();
            return `
                <div class="learning-search-item" onclick="openLearningSearchResult('${result.key}', ${result.pageIndex})">
                    <strong>${title} • Page ${result.pageIndex + 1}</strong>
                    <span>${snippet}</span>
                </div>
            `;
        })
        .join('');
}

function searchLearningAll(term) {
    const keys = getActiveLearningFilters();
    const lower = term.toLowerCase();
    const results = [];
    keys.forEach((key) => {
        const text = getLearningContent(key);
        if (!text) return;
        const pages = buildLearningPages(text);
        pages.forEach((page, pageIndex) => {
            const pageText = page.join('\n\n');
            const idx = pageText.toLowerCase().indexOf(lower);
            if (idx === -1) return;
            const start = Math.max(0, idx - 60);
            const end = Math.min(pageText.length, idx + lower.length + 60);
            const snippet = pageText.slice(start, end);
            results.push({ key, pageIndex, snippet });
        });
    });
    return results.slice(0, 12);
}

function getActiveLearningFilters() {
    const checks = document.querySelectorAll('.learning-filter');
    if (!checks.length) {
        return LEARNING_TOPIC_KEYS;
    }
    const active = [...checks].filter((c) => c.checked).map((c) => c.value);
    return active.length ? active : LEARNING_TOPIC_KEYS;
}

function setLearningFilters(selectAll) {
    const checks = document.querySelectorAll('.learning-filter');
    if (!checks.length) return;
    checks.forEach((check) => {
        check.checked = selectAll;
    });
    if (learningSearchTerm) {
        renderLearningSearchResults();
    }
}

function openLearningSearchResult(key, pageIndex) {
    learningPageState[key] = pageIndex;
    localStorage.setItem('lastLearningKey', key);
    showLearning(key);
    const body = document.getElementById('learningBody');
    if (body) body.scrollIntoView({ behavior: 'smooth' });
}

function getOpenMenuPage() {
    return document.querySelector('.menu-page.is-open');
}

function updateMenuScopeChips(page) {
    const setChip = (id, text) => {
        const chip = document.getElementById(id);
        if (chip) chip.textContent = text;
    };
    const adminLabel = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
    setChip('adminScopeChip', `Scope: ${adminLabel || 'Personal'}`);
    setChip('learningScopeChip', 'Learning Hub');
    setChip('formsScopeChip', 'Downloads');
    setChip('leadsScopeChip', 'Lead Center');
    setChip('appointmentsScopeChip', 'Quotation Scheduling');
    setChip('benSystemScopeChip', 'Facility Grouping');
    setChip('archivedScopeChip', 'Archive Vault');
    setChip('settingsScopeChip', 'Account');
    const detailTitle = document.getElementById('learningDetailTitle');
    if (detailTitle) {
        const title = detailTitle.textContent?.trim() || 'Topic View';
        setChip('learningDetailScopeChip', title.length > 32 ? `${title.slice(0, 32)}…` : title);
    }
    const teamLabel = adminRole === 'ADMIN' ? 'Admin (All Teams)' : adminTeam || 'Team';
    setChip('teamScopeChip', `Scope: ${teamLabel}`);
}

function updateMenuPageTopButton(forceHide = false) {
    const btn = document.getElementById('menuPageTopBtn');
    if (!btn) return;
    if (forceHide) {
        btn.classList.remove('is-visible');
        return;
    }
    const page = getOpenMenuPage();
    if (!page) {
        btn.classList.remove('is-visible');
        return;
    }
    btn.classList.toggle('is-visible', page.scrollTop > MENU_TOP_SCROLL_THRESHOLD);
}

function scrollMenuPageTop() {
    const page = getOpenMenuPage();
    if (!page) return;
    page.scrollTo({ top: 0, behavior: 'smooth' });
}

function handleMenuPageScroll() {
    const page = getOpenMenuPage();
    if (page) {
        page.classList.toggle('is-scrolled', page.scrollTop > 18);
    }
    updateMenuPageTopButton();
}

function isTypingTarget(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;
    const tag = target.tagName ? target.tagName.toLowerCase() : '';
    return tag === 'input' || tag === 'textarea' || tag === 'select';
}

function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function copyToClipboard(text, successMsg = 'Copied.') {
    if (!text) return;
    if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(text).then(() => showToast(successMsg, 'success')).catch(() => {
            showToast('Copy failed.', 'error');
        });
        return;
    }
    try {
        const input = document.createElement('textarea');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast(successMsg, 'success');
    } catch (_) {
        showToast('Copy failed.', 'error');
    }
}

function logExportHistory(label, count = 0) {
    if (exportFlowPending) return;
    if (exportFlowCanceled) {
        exportFlowCanceled = false;
        return;
    }
    const entry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        label,
        count
    };
    exportHistory.unshift(entry);
    exportHistory = exportHistory.slice(0, 50);
    localStorage.setItem('exportHistory', JSON.stringify(exportHistory));
}

function getLearningContent(key) {
    const override = learningOverrides && typeof learningOverrides[key] === 'string' ? learningOverrides[key].trim() : '';
    const looksLikeOldPlaceholder = /This module is being prepared\./i.test(override);
    if (override && !looksLikeOldPlaceholder) return override;
    const content = {
        jfaManual: `<span id="jfa-top"></span>
JFA Manual (Day 1)

Jump to:
<a href="#jfa-intro">Introduction</a> • <a href="#jfa-product">Product Overview</a> • <a href="#jfa-benefits">Product Benefits</a> • <a href="#jfa-qualify">Qualifying Criteria</a> • <a href="#jfa-sales">Sales Process</a> • <a href="#jfa-obtaining">Obtaining</a> • <a href="#jfa-afford">Affordability</a> • <a href="#jfa-cancel">Cancellations</a> • <a href="#jfa-pitch">Pitch Structure</a> • <a href="#jfa-growth">Growth Structure</a> • <a href="#jfa-compliance">Compliance</a>

INVESTMENT
ABSTRACT
Basic source of information for the training and development of a Junior Financial Advisor

INDEX
1. Matla Life Investment & RMA History
2. Market Overview
3. Product Objectives
4. Product Benefits
5. Target Market
6. Sales Process
7. Admin Process
8. Pitch Structure
9. Pitch Structure
10. Growth Structure

<span id="jfa-intro"></span>
INTRODUCTION

Who are we?
- Matla Life is a sales and marketing solutions company. We engineer services relevant to our diverse partners. Ultimately, we offer innovative resolutions for African business problems.

What do we do?
- We cater to the needs of our partners by providing sales, marketing and analytical tactics to ensure sales growth and market penetration.

Why do we do it?
- We endeavor to add value to our partners by engineering a package fully reflective of their bottom line.

[Back to top](#jfa-top)

JUNIOR FINANCIAL ADVISOR

Requirements:
- Production
- Recruitment
- Collection
- Teachbacks

Production
Consent Forms: 21
Converted sales: 10
Capital Legacy Wills: 6
MyCover: 4

Collection
80% of the leads submitted must be reachable. 70% must be convertible.

Teachbacks
JFA is expected to have all notes within the first week and apply the knowledge. The JFA must effectively share that knowledge with newer team members through instructed impacts.

Signature Sheet
Progress is monitored continuously with the signature sheet. Failure to attain all signatures within 2 months will lead to potential departure from company roster. This performance management is mandatory and is the JFA's responsibility.

[Back to top](#jfa-top)

<span id="jfa-product"></span>
PRODUCT OVERVIEW

We exist in a market that is very insurance reliant. Life is extremely spontaneous and it is vital to prepare for inconsistencies. Due to limited information and unethical brokers, funeral policies are overused. This has led to multiple funeral policies and rising premiums.
With our partnership with RMA, we provide a solution that relieves the client financially and improves convenience by consolidating policies.

[Back to top](#jfa-top)

<span id="jfa-benefits"></span>
PRODUCT BENEFITS
Distinctive attributes of the Consolidated Funeral Plan:
1. Combines multiple funeral covers into 1 policy
2. Saves a client up to 50% on current premiums without reducing cover
3. Better cover amounts
   - Main Life & Spouse: R100k
   - Parents & Ext: R70k
   - Children 0-6: R20k
   - Children 6-17: R50k
4. No waiting period if:
   - All current waiting periods served
   - Cover amounts are not increased and no new life is added
5. Annual premium payback: cashback a month after policy anniversary (average of 12 months premiums)
6. Body repatriation: air or road transport if death occurs 100km away from burial
7. Optional value added service package:
   - Airtime benefit (R350)
   - Grocery (R1400)
   - Wills & Testament (Link/Portal)
   - Tax & Financial Support (Phone)

Important points:
- Consolidates funeral policies ONLY
- Replacement product: previous policies are cancelled
- Can insure up to 22 lives
- Client chooses what to consolidate
- Top-up benefits or services on old policies do not carry over
- Maximum entry age is 75
- Policy amendment: changing cover amounts or adding a member
- Waiting period protects the insurer
- Adding a new life or increasing cover adds a 6 month waiting period for the increased amount
- Supporting documents: copy of ID and recent payslip

[Back to top](#jfa-top)

<span id="jfa-qualify"></span>
QUALIFYING CRITERIA
Who qualifies:
- Government employees earning R12 000+ per month (teachers, SAPS, nurses, etc.)
Where to find them:
- Government departments: schools, hospitals, police stations, courts, Home Affairs, etc.
- Excludes Metro Police, Municipalities, and other parastatals

[Back to top](#jfa-top)

<span id="jfa-sales"></span>
SALES PROCESS
Timeline overview:
Monday/Tuesday
1. Submit consent form
2. Fill out attendance register
3. Consent forms submitted to Reamo
4. Captured by admin
5. Given to FA and obtaining starts
Tuesday
1. Capturing
2. Quotation
3. Book appointment with client
Wednesday/Thursday
1. Present quotation
2. Sign on tablet
3. Prep client
Thursday
1. Submit to Dakalo to check for affordability
2. FA & Admin start with cancellations
3. Dakalo in-forces sale
Friday/Saturday
1. All business submitted on this day (falls under next week's submissions)
2. Get paid (if case affords)

[Back to top](#jfa-top)

<span id="jfa-obtaining"></span>
OBTAINING
The Consolidated Funeral Plan is a replacement product. Obtaining is the collection of a client's policy schedules from current insurers so the FA can draft a correct quotation.
1. What is to obtain?
- Collect policy schedules/policy documents from current insurers
2. Importance
- Needed to draft accurate quotations
- Avoid consolidating/cancelling wrong policies
3. What are policy schedules?
- Documents with client policy details: type, insured lives, cover amounts, start dates, etc.
4. How to obtain?
- Conference calling: insurer verifies with client
- Online portal: OTP access to policy info
- Client documents: copies already held by client
5. Who does it?
- Admin support or FA; JFAs can be trained to assist

[Back to top](#jfa-top)

<span id="jfa-afford"></span>
AFFORDABILITY
Government allows only 15% of basic salary to be deducted by insurance.
1. What is affordability?
- The allowable 15% deduction limit
2. Why it matters?
- Determines whether a policy can go in force
3. How to calculate?
- Example: 15% of R20k = R3000
- If current policies already deduct R2000, available is R1000
- If quote is R1200, affordability fails
4. When to check?
- After quotation is done

NB: If a client has only 1 funeral cover, we may not save them money. We add value with increased cover and services.

[Back to top](#jfa-top)

<span id="jfa-cancel"></span>
CANCELLATIONS
Cancellations prevent double debits and enable affordability.
1. What are cancellations?
- Termination of existing policies being replaced
2. Why important?
- Avoid double debits
- Create affordability
- Enable refunds if double debited
3. What is a double debit?
- Old insurer and RMA both debit in same cycle
4. Who does cancellations?
- FA, admin support, or the client
5. How?
- Email cancellation request
- Conference call for immediate termination
- Branch walk-ins for formal cancellation and refunds

[Back to top](#jfa-top)

<span id="jfa-pitch"></span>
PITCH STRUCTURE

INTRODUCTION (Step 1)
Have SEX with your customer:
- S: Smile/polite
- E: Eye to eye contact
- X: Excitement
Pause after intro for response.

Greeting example:
"Good day sir/ma'am. My name is ______ from Matla Life Investments in partnership with RMA. How are you today?"

SHORT STORY (Step 2)
KISS principle: Keep it short and simple.
Example:
We are not here to sell today. We found many people overpay for multiple funeral policies that cover the same people. Do you have any funeral policies?

PRESENTATION (Step 3)
Needs analysis:
- Assupol, Old Mutual, Avbob?
- How much are you spending? R800/R900 or above?
- Do you have kids? How many?

Brief description:
Replacement service that can save up to 50% by combining funeral policies into one, with no loss of benefits and no waiting periods on existing cover.

Stress the deal:
- "Can you see how much value this can give you?"
- "Can you see how much money this can give you?"

CLOSE (Step 4)
Assume the sale:
- Book appointment with qualified FA
Ask yes-yes question:
- "When can the FA see you? Tomorrow during lunch or later?"
Explain consent form, supporting docs, obtaining process, and agree on time.

REHASH (Step 5)
"Who else do you know that needs my services?"

[Back to top](#jfa-top)

<span id="jfa-growth"></span>
GROWTH STRUCTURE
Time frame and roles:
12 months: Regional Manager (Basic + Comm), 2 Sales Managers, 8 Team Leaders, 16 TIC, 32 FAs, 160 Lead Generators
6 months: Sales Manager, 2 Team Leaders, 4 TIC, 16 FAs, 80 Lead Generators
3 months: Team Leader, 2 TIC, 4 FAs, 20 Lead Generators
4 months: 2 TIC, 2 FAs, 10 Lead Generators
2 months: Financial Advisor, 5 Lead Generators
2 months: Junior Financial Advisor

[Back to top](#jfa-top)

<span id="jfa-compliance"></span>
COMPLIANCE LEGISLATION
FSCA - Financial Services Conduct Authority
Compliance means abiding by laws and company policy.
Key laws include:
- Financial Sector Regulation Act 9 of 2017
- FAIS Act 37 of 2002
- Protection Of Personal Information Act 4 of 2013

Fraud
Wrongful or criminal deception intended to result in financial or personal gain.
Examples:
- Offering a client money to sign
- Someone else selling on your behalf
- Forging a client's information or signature
- Lying about the product

[Back to top](#jfa-top)

FINANCIAL SERVICES SECTOR ENVIRONMENT
FAIS Act regulates the sector for consumer protection and professionalization.
Role players:
1. FSCA - ensures FAIS Act is enforced
2. FSPs - institutions selling financial products (e.g., Matla Life Investments, RMA)
3. Key Individuals - ensure FAIS Act is implemented (e.g., Mr Zolani Mpungutye)
4. Representative - provides financial services to clients (you)

TCF - Treating Customers Fairly
Outcome 1: Culture & Governance - fair treatment is core
Outcome 2: Product Suitability - products designed for client needs
Outcome 3: Disclosure - clear communication before/during/after sale
Outcome 4: Suitable Advice - advice fits customer circumstance
Outcome 5: Performance & Service - deliver what was promised
Outcome 6: Claims, Complaints & Changes - clients should not face difficulties when amending or claiming

[Back to top](#jfa-top)`,
        marketing: `Imagine This 🎨
Picture a busy marketplace in ancient times. Stalls line the street, each selling something different: spices, fabrics, tools. Every merchant is shouting, waving, or arranging their goods to catch the eye of passersby.
Now, some merchants are chaotic—yelling randomly, changing prices every hour, or forgetting to show up. Others have a system:
• They know when to open and close.
• They display goods in a neat, attractive way.
• They have a routine for greeting customers.
• They track which products sell best and adjust accordingly.
That organized routine is what we call a marketing system today. It’s not just shouting “buy my stuff!”—it’s a structured way of attracting, engaging, and keeping customers.

Breaking It Down Step by Step
Think of a marketing system as a machine with gears. Each gear represents a part of the process, and when they all turn smoothly, the business grows.
1. Awareness Gear
• Purpose: Make people notice you exist.
• Modern Example: Ads on Instagram, flyers, or word-of-mouth.
• Marketplace Analogy: The merchant places colorful fabrics at the front of the stall to catch attention.
2. Interest Gear
• Purpose: Spark curiosity.
• Modern Example: A free sample, a catchy slogan, or a blog post.
• Marketplace Analogy: The spice seller lets you smell a pinch of cinnamon.
3. Decision Gear
• Purpose: Help people choose you over competitors.
• Modern Example: Discounts, testimonials, or clear explanations of benefits.
• Marketplace Analogy: The fabric seller shows how durable the cloth is compared to others.
4. Purchase Gear
• Purpose: Make buying easy and pleasant.
• Modern Example: Smooth checkout, multiple payment options.
• Marketplace Analogy: The merchant wraps your goods neatly and thanks you.
5. Retention Gear
• Purpose: Keep customers coming back.
• Modern Example: Loyalty programs, follow-up emails, personalized offers.
• Marketplace Analogy: The spice seller remembers your favorite blend and offers you a deal next time.

Why It Matters
Without a system, marketing is like throwing darts blindfolded—you might hit the target once, but most of the time you waste effort. With a system, every dart is aimed carefully, and you can measure how close you’re getting.
• Predictability: You know what works and can repeat it.
• Efficiency: Less wasted time and money.
• Growth: Systems scale—what works for 10 customers can be expanded to 1,000.

Vivid Example in Today’s World
Imagine you’re selling handmade sneakers online:
• Awareness: TikTok videos showing your designs.
• Interest: A blog post about how your sneakers are eco-friendly.
• Decision: Reviews from happy customers.
• Purchase: A clean website with “Buy Now” buttons.
• Retention: A thank-you email with a discount for their next pair.
That’s a marketing system in action—it’s the invisible engine behind every successful business.

Quick Tips
• Keep a simple tracker: Awareness → Interest → Decision → Purchase → Retention.
• Improve one gear at a time (don’t fix everything at once).
• Review results weekly and adjust your message or channel.`,
        loa: `The Core Idea 🎯
The Law of Averages is the belief that if you repeat an action enough times, the results will eventually balance out to a predictable ratio.
Think of it like planting seeds: not every seed grows, but if you plant enough, you’ll see a pattern.

Step-by-Step Breakdown
1. The Ratio (1:10)
• In sales, people often say: “For every 10 people you talk to, 1 will buy.”
• That’s the Law of Averages in action—you don’t know which person will say yes, but you know the ratio will hold if you keep trying.
2. Short-Term Chaos
• If you only talk to 2 people, both might say no.
• That doesn’t mean the system is broken—it just means you haven’t given the averages enough chances to show themselves.
3. Long-Term Balance
• Over 100 conversations, you’ll likely see about 10 sales.
• The more you repeat, the closer you get to the expected ratio.

Vivid Example 🌍
Imagine you’re a street performer juggling to attract tips:
• You perform for 10 groups of people.
• 9 groups clap but walk away.
• 1 group drops money in your hat.
That’s the 1:10 ratio. If you stop after 3 groups, you might think, “This doesn’t work.” But if you keep going, the averages kick in.

Why It Matters
• In Sales: It teaches persistence. Don’t quit after a few rejections—your “yes” is hiding in the averages.
• In Life: It reminds us that effort compounds. Success isn’t about one lucky break; it’s about showing up enough times for the odds to work in your favor.
• In Business: It helps forecast results. If you know your ratio, you can predict outcomes (e.g., 100 calls → 10 sales → R1,000 profit).

Marketplace Analogy 🏺
Back to our ancient marketplace:
• A spice seller knows that out of every 10 people who stop at his stall, 1 will buy.
• He doesn’t chase the 9 who walk away—he focuses on talking to more people, because the ratio guarantees results over time.

Quick Tips
• Track your ratio weekly (e.g., 1:8 or 1:12).
• Focus on volume and consistency, not perfection.
• Celebrate effort milestones, not just wins.`,
        five: `5 Steps ⚙️
Step 1: Intro
• Meaning: This is your opening move—breaking the ice and making contact.
• Analogy: Think of a merchant in the marketplace smiling and saying, “Welcome, traveler!” before showing his goods.
• Ratio in Action: Out of 10 intros, maybe only 1 person will stop and listen—but that’s enough to start the process.

Step 2: Short Story
• Meaning: A quick, engaging explanation that builds curiosity. It’s not the full pitch—just a teaser.
• Analogy: A spice seller says, “These cinnamon sticks come from the mountains—rare and full of flavor.”
• Ratio in Action: Out of 10 short stories, 1 person will lean in and want to hear more.

Step 3: Presentation
• Meaning: This is the main pitch—showing the product or service clearly, with benefits highlighted.
• Analogy: The tailor lays out the suit, lets you feel the fabric, and explains why it lasts longer.
• Ratio in Action: Out of 10 presentations, 1 person will be convinced enough to move forward.

Step 4: Close
• Meaning: Asking directly for the sale. This is where persistence matters—you don’t leave it vague.
• Analogy: The merchant says, “Shall I wrap this up for you?” instead of waiting for you to decide silently.
• Ratio in Action: Out of 10 closes, 1 person will say yes. The other 9 may hesitate, but the averages guarantee that one will commit.

Step 5: Rehash
• Meaning: After the sale, reinforce the decision and open the door for future sales. It’s about maximizing the relationship.
• Analogy: The spice seller, after selling cinnamon, says, “Next time, you might enjoy our nutmeg—it pairs beautifully.”
• Ratio in Action: Out of 10 rehashes, 1 person will buy again or refer someone else.

Putting It All Together 🌍
The Law of Averages says:
• If you repeat these 5 steps consistently, the ratio (like 1:10) will reveal itself.
• You don’t know which person will be the “yes,” but you know that if you keep moving through the steps, the numbers will balance out.
• Example: If you want 20 sales, you’ll need about 200 full cycles of Intro → Short Story → Presentation → Close → Rehash.

Quick Tips
• Write one strong line for each step and practice it daily.
• Keep the “Short Story” under 20 seconds.
• Always end with a clear next step (a question or invitation).`,
        eight: `1. Identify Your Target Market (WHO you serve)

What this means:
You must clearly define who your ideal customer is before you try to sell anything.

Why this matters:
You cannot sell to everyone. If you try, your message becomes weak and confusing.

Key questions to ask:

Who has the problem my product solves?

What age, gender, job, income level?

Where do they spend time (online or offline)?

What frustrates them?

Example:
If you sell a fitness program:

❌ “People who want to get fit”

✅ “Busy professionals aged 25–40 who want to lose weight without going to the gym”

Marketing rule:

If you don’t know exactly who you’re talking to, no one listens.

2. Understand the Customer’s Problem (WHY they care)

What this means:
You must deeply understand the pain, fear, or desire your customer is experiencing.

People don’t buy products.
They buy solutions to problems or paths to desired outcomes.

Types of problems:

Physical – weight, health, money

Emotional – stress, fear, insecurity

Social – status, approval, confidence

Example:
A person doesn’t buy a laptop because it’s fast.
They buy it because:

Their old one wastes time

They feel embarrassed at work

They want to be more productive

Marketing rule:

The stronger the pain you address, the easier the sale.

3. Create a Compelling Offer (WHAT you sell)

What this means:
An offer is not just a product.
It is everything the customer gets, packaged to feel valuable and low-risk.

A strong offer includes:

The product or service

Bonuses (extras)

Guarantees

Price

Clear outcome

Example:
❌ “Online trading course – R2,000”
✅ “8-week beginner trading course + live mentorship + risk management templates + 30-day money-back guarantee”

Why this matters:
People don’t compare prices — they compare perceived value.

Marketing rule:

Make your offer so good people feel stupid saying no.

4. Craft Your Message (HOW you communicate)

What this means:
You now translate the customer’s problem and your offer into simple, emotional language.

Your message must answer:

What problem do you solve?

Who is this for?

How does life improve after using this?

Why should they trust you?

Good messaging uses:

Simple words (no jargon)

Emotion

Benefits, not features

Example:
❌ “Our software uses advanced algorithms”
✅ “Finish your work in half the time without stress”

Marketing rule:

Clarity beats cleverness every time.

5. Choose Your Marketing Channels (WHERE you show up)

What this means:
You decide where to place your message so the right people actually see it.

Common channels:

Social media (Instagram, TikTok, LinkedIn)

Email

Websites & landing pages

Ads

Word of mouth

Key idea:
Your customers already hang out somewhere.
You go there, not the other way around.

Example:

Professionals → LinkedIn

Young audience → TikTok / Instagram

Businesses → Email

Marketing rule:

Be where your customers already are.

6. Capture Leads (TURN attention into contact)

What this means:
A lead is someone who has shown interest and given you a way to contact them.

This is critical because most people won’t buy immediately.

Common ways to capture leads:

Free guide or checklist

Free consultation

Email newsletter

Free trial

Example:
“Download our free beginner trading checklist”
→ Customer gives email
→ Now you can follow up

Marketing rule:

Attention is rented. Leads are owned.

7. Nurture Trust & Build Relationship (MAKE them comfortable)

What this means:
You educate, help, and build trust before asking for the sale.

People buy from:

Brands they trust

People they understand

Solutions they believe will work

How to nurture:

Emails with useful tips

Social proof (testimonials)

Educational content

Stories

Example:
Before selling a fitness program:

Teach basic exercises

Share success stories

Explain common mistakes

Marketing rule:

Trust is built before money is exchanged.

8. Close the Sale & Retain the Customer (GET paid & keep them)

What this means:
You clearly ask for the sale and then focus on keeping the customer happy.

Closing the sale:

Clear call-to-action (“Buy now”, “Book a call”)

Remove friction (simple checkout)

Reassure with guarantees

Retention is crucial because:

Repeat customers cost less

They refer others

They increase lifetime value

After the sale:

Deliver results

Follow up

Upsell or cross-sell responsibly

Marketing rule:

The easiest sale is the second sale.

The Entire System in One Flow

Who are you selling to?

What problem do they have?

What solution do you offer?

How do you explain it clearly?

Where do you reach them?

How do you capture interest?

How do you build trust?

How do you close and retain?

Quick Tips
• Write a one-line offer for each step to keep your message clear.
• Keep one primary channel per campaign (don’t scatter effort).
• Track one lead metric (leads, calls, demos) and one conversion metric.`,
        fugi: `The FUGI framework explains why people say “yes”.
It focuses on the psychological drivers behind buying decisions.

FUGI = Fear, Urgency, Greed, Indifference

Every buying decision is influenced by one or more of these forces—whether people realize it or not.

1. Fear – “What happens if I DON’T act?”
What Fear means in sales

Fear is the desire to avoid pain, loss, or negative consequences.

Humans are wired to avoid loss more strongly than they seek gain.

People buy to:

Avoid missing out

Prevent failure

Protect themselves

Reduce uncertainty

Common fears customers have

Losing money

Wasting time

Falling behind others

Making the wrong decision

Being embarrassed or judged

Example

A person doesn’t buy antivirus software because it’s “advanced.”
They buy because they’re afraid of:

Getting hacked

Losing personal data

Financial theft

How marketers ethically use Fear

Highlight risks of inaction

Show consequences clearly (not exaggerated)

Position your product as protection

Example message:
“If you don’t manage your finances now, you’ll still be stuck paycheck-to-paycheck five years from now.”

Key rule

Fear motivates action faster than pleasure.

2. Urgency – “Why must I act NOW?”
What Urgency means in sales

Urgency removes procrastination.

Most people delay decisions even when they want something.
Urgency answers the question:

“Why not later?”

Why urgency works

Humans prioritize immediate threats and opportunities

Time limits force decisions

Scarcity increases perceived value

Common urgency triggers

Limited time offers

Limited stock

Deadlines

Price increases

Example

People often want to get fit “eventually.”
Urgency converts that into:

“Start today”

“Offer ends tonight”

“Only 5 spots left”

Ethical urgency vs manipulation

Ethical:

Real deadlines

Genuine limits

Honest scarcity

Unethical:

Fake countdown timers

False “last chance” claims

Key rule

Without urgency, interest dies.

3. Greed – “What do I GAIN?”

(Greed here does not mean selfishness — it means desire for improvement.)

What Greed means in sales

Greed is the desire for:

More money

Better results

Higher status

Easier life

Faster outcomes

People are drawn to upside potential.

Examples of greed-based motivations

“Make more money”

“Save time”

“Increase confidence”

“Get ahead of others”

“Live better with less effort”

Example

Someone buys a trading course because:

They want financial freedom

They want extra income

They want control over their time

How marketers use Greed

Focus on benefits and outcomes

Emphasize ROI (Return on Investment)

Show transformation (before → after)

Example message:
“Turn your spare time into an extra R10,000 per month.”

Key rule

People buy outcomes, not processes.

4. Indifference – “Why should I care at all?”
What Indifference means in sales

Indifference is the default state of your audience.

Most people:

Aren’t thinking about you

Aren’t actively shopping

Don’t feel emotional yet

Your first job in marketing is to break indifference.

Why indifference is the biggest obstacle

If someone doesn’t care:

Fear doesn’t work

Urgency doesn’t work

Greed doesn’t work

They must first be engaged emotionally or intellectually.

How to overcome indifference

Be relevant

Speak directly to their situation

Use patterns they recognize

Ask compelling questions

Example

❌ “We offer business consulting services”
✅ “Most small businesses fail because of one mistake—are you making it?”

Key rule

If you don’t interrupt indifference, nothing else matters.

How FUGI Works Together (Very Important)

People rarely buy for only one factor.

Most decisions look like this:

Fear of staying the same

Greed for a better outcome

Urgency to act now

Indifference already broken by relevance

Example: Fitness Program

Fear: “I’m getting unhealthy”

Greed: “I want confidence and energy”

Urgency: “Summer is in 8 weeks”

Indifference: Broken by “This program is for busy people who hate gyms”

FUGI Applied to a Simple Sales Message

“If you don’t take control of your money now (Fear), you’ll still be struggling years from today.
This system helps beginners grow steady income (Greed) without quitting their job.
Enrollment closes Friday (Urgency).
If you’re tired of being stuck, this is for you (Indifference broken).”

Why FUGI Is So Powerful

It explains human behavior, not tactics

It works in ads, emails, conversations, pitches

It applies to any product or service

It aligns with how the brain actually makes decisions

One-Sentence Summary

People buy when they care (Indifference), want more (Greed), fear loss (Fear), and feel compelled to act now (Urgency).

Quick Tips
• Use 1–2 FUGI angles per message (not all four at once).
• Be ethical with urgency (real deadlines only).
• Always show the “safe next step” to reduce fear.`,
        impulse: `The IMPULSE framework explains why people buy in the moment, often emotionally first and logically later.

IMPULSE = Immediacy, Momentum, Proof, Simplicity, Emotion

These factors reduce thinking friction and accelerate decisions.

1. Immediacy – “I want it NOW”
What Immediacy means in sales

Immediacy is the desire for instant gratification.

Humans naturally prefer:

Fast results over slow results

Convenience over effort

Instant reward over delayed reward

Why immediacy works

The brain discounts future rewards.
The closer the reward feels, the more valuable it becomes.

Examples

Same-day delivery

Instant access after payment

“Start in 5 minutes”

“Download immediately”

Example message

“Get access instantly—no waiting, no setup.”

Key rule

The shorter the time to reward, the higher the conversion.

2. Momentum – “I’ve already started, I might as well continue”
What Momentum means in sales

Momentum is the psychological tendency to continue once action has begun.

Once someone says “yes” to a small action, a bigger “yes” becomes easier.

Why momentum works

Commitment creates consistency

Small actions reduce resistance

Progress feels good

Examples

Free trials

Step-by-step onboarding

Low-commitment entry offers

Example

A free checklist → email signup → low-cost product → premium offer

Example message

“You’re already halfway there—finish setting this up.”

Key rule

Action creates more action.

3. Proof – “Others are doing it, so it must be safe”
What Proof means in sales

People look to others to decide what’s correct—especially when unsure.

This is called social proof.

Types of proof

Testimonials

Reviews

Case studies

User counts

Before-and-after stories

Why proof works

Reduces risk

Builds trust fast

Normalizes the decision

Example

“Trusted by 25,000 users”
“4.8-star rating from real customers”

Key rule

If people like me succeeded, I probably will too.

4. Simplicity – “This looks easy”
What Simplicity means in sales

Complexity kills impulse.

If something looks:

Confusing

Technical

Time-consuming

People hesitate or leave.

Why simplicity works

The brain avoids effort.
Clear, simple choices feel safer.

Examples

One-click checkout


Clear pricing

Plain language

Step-by-step explanations

Example message

“3 simple steps. No experience required.”

Key rule

Confused minds do not buy.

5. Emotion – “This feels right”
What Emotion means in sales

Emotion is the engine behind impulse buying.

Logic justifies the purchase after the decision is made.

Core buying emotions

Hope

Excitement

Relief

Confidence

Belonging

Examples

Inspiring stories

Transformation imagery

Identity-based messaging

Example message

“Imagine waking up confident, energized, and in control.”

Key rule

People buy emotionally and defend logically.

How IMPULSE Factors Work Together

Impulse purchases rarely rely on one factor alone.

A typical impulse decision looks like this:

Emotion sparks desire

Simplicity removes friction

Proof removes fear

Immediacy pulls the trigger

Momentum carries them through checkout

IMPULSE Applied to a Simple Sales Message

“Start today and get instant access (Immediacy).
Join 12,000 beginners already using this system (Proof).
Set it up in 10 minutes—no experience needed (Simplicity).
You’re already closer to freedom than you think (Momentum + Emotion).”

How IMPULSE Differs from FUGI (Important)

FUGI explains why people care

IMPULSE explains why they act immediately

They work best together.

One-Sentence Summary

Impulse buying happens when emotions are high, effort is low, proof is strong, rewards are immediate, and action is already in motion.

Quick Tips
• Reduce steps (less clicking = more conversions).
• Add proof near the call-to-action (reviews, numbers).
• Use clear, simple wording for the next step.`,
        cod: `MATLA LIFE INVESTMENT
C.O.D. (Cycle Of Development) 2 Notes

Promoting Tools
What: Tools we use to promote the company and the opportunity to new guys and customers.
Why: To promote the expansion and opportunity.
How:
1. The System: The way the company works and marketing systems.
2. The Atmosphere: Teaching and learning the system.
3. Yourself: Goals (short, medium, long term), progression, and setting examples.
4. Managers: Someone who has finished the program shares experiences and proof.
5. Advertising: Magazines, bulletins, whiteboards, and worldwide growth.
6. The Merchandise: Clients we deal with, price, and product quality.
7. Trainers Meetings, Relax and Relate weekends, Road trips: Hot shots, learning experience, expansion.
8. Opportunity: The use of promoting tools.
When: From day one until you own real promotion.

Leading a Ride-Out (R/O)
Your ride out is your responsibility all day, no mishaps. You are put together for a reason.
Find out the R/O situation the night before or first thing in the morning.
Make this part of your routine: attitude, comfort zones, pitch, goals, work ethic, pace.

Mornings
1. Get set up quickly and properly with the R/O trainer; be set up before 7:00.
2. Build a game plan and get on the white boards.
3. Go over R/O goals for the day (tick sheet).
4. Teach relevant topics and give individual attention.
5. Be prepared: marker, tick sheet, impacts, application forms.
6. Set R/O up with relevant impacts; stay with R/O unless in another impact.
7. Jump into pitching circles; belt loop your R/O.
8. Practice goals: pitch together 10-15 times and build confidence.
9. Take R/O to top trainers for specific topics.

Build - Break - Build
1. Build up positives.
2. Break down with critique.
3. Build up again and end positive.

Morning Meeting
Stick with your R/O and get them into the rhythm and excitement.
Buddy up and build relationship.
During trainers meeting, set R/O into relevant impacts.
Prepare for observation: "you are my priority."
Keep R/O occupied in atmosphere; set up with top guys and pitching circles.
Walk down together.

Ride Out to the Field
1. Build relationship: break ice, find hotspots, hobbies, interests.
2. Keep conversation light and fun; avoid politics and religion.
3. Mentality: talk about winning and set a team goal.
4. Re-stress the importance of a tick sheet.

In the Field
Be on the ball; have apps and pitch file ready.
Swap phone numbers; if no phone, find a pay phone or borrow.
Check pitch file, apps, ID badge.
Watch R/O pitch for 20 minutes; build, break, build.
Do not change entire pitch at once; leave R/O confident.
Once confident, send R/O out and give a side option.
Focus on system and goals, not money or bell.
Set territory loops toward each other; meet up regularly.
Check tick sheet, attitude, work ethic, territory.
Expect negatives and overturn them (e.g. rehash territory).
Use "feel, felt, found."
Retrain if needed: demonstrate quickly.
If R/O battling, help 15-20 minutes; isolate problem, rebuild confidence.
If R/O pumping, boost and let them fly.
Meet up every hour for new R/O; every +/- 2 hours if confident.
Take the risk with security; you pitch closest to security.
Rendezvous in time to return; around 16:30 (V-town around 16:00).

Ride Back to Office
No breaks; teach good work ethics.
Get R/O pumped for atmosphere and stay positive.
Show urgency and excitement.

Back in the Office
1. Be urgent and together.
2. Do daily break down.
3. Stand together for bells; keep excitement and crew flow.
4. Hand backs with build - break - build to the trainer.
Find positives and overturn negatives.
Promote the R/O situation; never make excuses.
Relate the day back to 5 and 8 working system.
KISS for maximum impact and effect.
Keep private feedback for after, be honest.
Thank the R/O for the day and leave them positive.

Office 15:30
Be urgent and together.
Feedback, DBD, de-app.
Book appointments; be out by 16:00.

Daily Break Down
Take it seriously and take control.
Get inside the R/O head and involve them in problem solving.
Make sure the R/O understands why you write info on boards.
Get the day's tick sheet and assess goals.
Relate all info to using the system correctly.
Do not just tell; show by example.
Make goals relevant to R/O situation and change their future.
Overturn negatives and excuses; know how the day could have been better.
Evaluate number of people seen and presentations; check sales per customer.

Impacts on Impacts
What: Sharing and transferring knowledge with new people.
Why: Motivate, educate, and develop new people. Applied knowledge equals power.
How: 10 key points.
1. S.E.X keeps people interested and shows enthusiasm.
2. K.I.S.S: Keep It Short and Simple.
3. Do not overload; give need-to-know info and ask questions.
4. Keep it relevant to the person and office.
5. 5 Steps: Intro, Short story, Present, Close, Rehash.
6. 8 Steps: Great attitude, be prepared, work territory correctly, be in control.
7. Involvement: encourage participation and input.
8. Bullet points: simplify and explain to apply.
9. Understanding: know what you teach and keep interest.
10. Have fun whilst teaching.
When: Every time you teach people.

Topics for Impacts
Overturning common negatives, changing over from the competition, 8 steps to good work habits, toolbox, rehashing the deal, rehashing territory, working territory, L.O.A., impulse buys and logic buys, pro and pre-active overturning negatives, impulse curve, use of T.O.V., body language, persistence vs good customer service, pre-closing, multiple closing, leading questions, selling yourself, building trust, P.M.A., having fun, excitement, company structure, comfort zones, thinking big.

Goal Setting and Tick Sheet Basics
Result is your "what". Action is your "how".
Track how many people you see per hour.
Tick Sheet terms:
Total people seen: everyone spoken to during the day.
Total presentations: people you put product in hand (step 3 onwards).
Total apps: total apps signed in the field.
Conversion rate: total people seen divided by total apps.
Presentation rate: percentage of people you get product in hand (presentations divided by total people seen).`,
        cross: `CROSS-SELLING

Core Definition
Cross-selling is using multiple relevant products or services to meet one client's financial needs in a more complete way.

What this means in practice:
- You do not force extra sales.
- You identify real needs and match suitable products.
- You improve client outcomes while increasing consultant productivity.

Why Cross-Selling Matters
From your training notes:
- It helps properly service the client.
- It allows a consultant to maximize selling opportunities.
- It positions the consultant, client, and business more favorably financially and operationally.
- It increases earning potential through better service delivery.

Expanded value:
1. Better client protection:
   One product rarely solves every risk. A smarter bundle creates stronger financial resilience.
2. Better retention:
   Clients with multiple relevant products are less likely to cancel.
3. Better trust:
   Clients feel advised, not sold to, when recommendations are connected to their goals.
4. Better long-term income:
   Stronger portfolios, cleaner verifications, and better persistency improve results over time.

What Is Cross-Selling?
Use multiple products and services to meet a client's financial objectives and close risk gaps.

Simple model:
- Primary need -> Primary product
- Secondary need -> Supporting product
- Future need -> Follow-up product

Example:
Client wants funeral cover today.
You also identify debt pressure and income risk.
You recommend:
- Funeral product for immediate family burden protection
- Suitable consolidation option for premium efficiency
- Follow-up life solution for income replacement planning

Why It Is Important To Cross-Sell
1. Gives the client options:
   Clients can choose according to affordability and urgency.
2. Improves financial insight:
   You help client understand where money leaks and where protection is missing.
3. Increases revenue ethically:
   More suitable solutions means more value delivered and more business growth.
4. Strengthens after-sales:
   Service quality improves when product decisions were intentional from day one.

Who Cross-Sells?
Lifestyle Consultant
- Leads the needs analysis and structured consultation.
- Uses multiple products intentionally where relevant.

Verification Team
- Reinforces value after point of sale.
- Flags deferred needs where a client asked to revisit later.
- Supports continuity between sale, onboarding, and service.

How To Cross-Sell (Operational Workflow)
1. Training first
- Know each product deeply: eligibility, exclusions, premium logic, claim process, and ideal client profile.
- If product knowledge is weak, do not pitch it yet.

2. Survey before pitch
- During meet-and-greet, complete a needs survey.
- Capture family structure, income realities, current cover, debt pressure, and financial goals.

3. Structured consultation
- Use consultation guidelines to keep the conversation intentional.
- Move from discovery -> gap analysis -> recommendation -> confirmation.

4. Customer service follow-through
- Post-sale service builds trust.
- Clients are more open to additional relevant products when they experience real support.

5. Verification touchpoint
- Confirm client understanding.
- Revisit deferred opportunities with permission.

When To Cross-Sell
From your training notes:
- During all consultations.
- During verifications and customer service.

Working rhythm:
- Consultation day: identify full need map.
- Verification stage: confirm fit and uncover deferred needs.
- After-sales stage: review changes in client life and adjust cover.

Cross-Selling Conversation Script (Easy Flow)
Step 1 - Permission
"Can I quickly show you one or two additional options that could close the gaps in your current setup?"

Step 2 - Gap
"Right now this product covers X. The remaining risk is Y."

Step 3 - Fit
"This second option is designed for Y and keeps your total plan balanced."

Step 4 - Control
"Let's decide what starts now and what we schedule for later so it stays affordable."

Step 5 - Confirm
"Are you comfortable with this recommendation and the reason behind each product?"

Cross-Selling Do's
- Ask questions before recommending.
- Match product to need, not to quota.
- Use plain language and examples.
- Explain total monthly impact clearly.
- Document what client accepts now and later.
- Follow up exactly when promised.

Cross-Selling Don'ts
- Don't stack products without clear need.
- Don't hide exclusions, waiting periods, or cost changes.
- Don't pressure a client into immediate decisions.
- Don't overcomplicate with jargon.

Quality Checklist Before You Close
- Need identified and written clearly.
- Product recommendation linked to each need.
- Affordability verified.
- Benefits and limitations explained.
- Client understanding confirmed.
- Deferred opportunities logged for follow-up.

Mini Case Study
Client profile:
- 34 years old, two children, has one small funeral policy, unstable monthly cash flow.

Needs identified:
- Funeral shortfall risk
- Premium efficiency concern
- Long-term family protection gap

Recommended structure:
- Keep immediate funeral protection in force.
- Add relevant consolidation path to remove overlap and improve value.
- Book follow-up for life cover review once budget stabilizes.

Outcome:
- Client gets practical protection now.
- Advisor keeps trust high and creates future pipeline.

One-line Principle
Cross-selling is not "selling more". It is solving more of the right problems in one trusted relationship.`,
        consolidation: `Product Knowledge - Consolidation

Consolidated Funeral Product (RMA Life)
Version context: July 2022 training material.

1) Product Overview
Consolidated Funeral is a traditional funeral policy aimed at:
- Replacing existing funeral policies, or
- Consolidating multiple funeral policies held with different insurers into one policy underwritten by RMA Life.

Core promise:
- Similar or improved cover and benefits,
- At a competitive or even cheaper premium.

What the product pays:
- Lump sum benefit on death of insured lives.
- Embedded features included in policy design.
- Optional features available at extra premium.

Target market:
- Low to medium income earners in South Africa,
- Especially clients already holding several funeral policies.

Distribution:
- Initial channel is Matla Life.
- Can expand to additional channels in future.

2) Summary of Benefits
Main funeral benefits:
- Funeral lump sum death benefit.
- Optional annual premium and benefit increases.
- Up to 30-day free cover.
- Optional annual premium payback.
- Value Added Services (VAS): embedded and optional bundles.

VAS provider:
- EuropAssist (third-party provider).
- VAS has a compulsory bundle and a voluntary bundle.

3) Cover Amount Rules
Cover starts at R10 000 and can go up to R100 000.

Important rule:
- Cover for any insured life may not exceed the Main Member's cover.

Maximums by life type:
- Main Member: up to R100 000
- Spouse: up to R100 000
- Parents and Extended Family: up to R70 000
- Stillborn child: up to R3 000
- Children 0-6 years: up to R20 000
- Children 6-17 years: up to R50 000

4) Annual Premium and Benefit Increase
Policyholder chooses one option:
1. No annual increase
2. 5% premium increase with 4% benefit increase
3. 10% premium increase with 8% benefit increase

Increase month:
- Policyholder elects the month increases apply.

Age stop:
- Annual increases stop when policyholder reaches age 65.

Worked example (5% premium / 4% benefit):
- At age 50: Cover R10 000, Premium R100
- Age 51: Cover R10 400, Premium R105
- Age 52: Cover R10 816, Premium R110.25
- Age 64: Cover R17 317, Premium R198
- Age 65+: Cover R17 317, Premium R198 (no further increases)

5) Up to 30-Day Free Cover
No premium payable for up to 30 days before first premium collection date.

Example:
- Application: 01 Mar 2022
- First collection date: 01 May 2022
- Free cover starts: 01 Apr 2022

6) Annual Premium Return
Premium return is paid at month-end after 12 consecutive paid months.
Returned amount is the average premium over the previous 12 months.

Example pattern:
- 01/04/2022 to 01/03/2023 at R100 -> return R100
- Mixed period with R100 then R105 -> average return R102.50
- Mixed period with R105 then R110.25 -> average return R107.63

7) Value Added Services (VAS)
Compulsory VAS:
- Repatriation:
  Assists with road or air transport of mortal remains to a funeral home nearest normal residence.
  Only available where there is a valid funeral claim.
  First 100 km between place of death and place of burial is excluded.

Important VAS rule:
- No cash payout or substitution for VAS benefits.
- Access via EuropAssist Contact Centre.

Voluntary VAS:
- Airtime benefit:
  Airtime voucher worth R350 on death of insured family member (valid underlying claim required).
- Grocery:
  Voucher worth R1 400 on death of insured life (valid underlying claim required).
- Wills and Testaments:
  Access to portal/call centre support for drafting wills.
- Tax and Financial Support:
  Access to support line for tax and finance guidance.

8) Role Players
Underwriter:
- RMA Life (Long-term Insurance Act context).

Administrator:
- RMA Admin Services.

Policyholder:
- Main life insured and contracting party.

Beneficiary:
- Person nominated to receive benefit.
- Policyholder is always beneficiary for applicable benefits unless main member death rules apply.

Distribution:
- Matla Life (initial distribution channel).

9) General Policy Information
Lives covered:
- Up to 22 lives on one policy.

Definitions:
- Main Member: policyholder shown on schedule.
- Spouse: legally recognized husband/wife, life partner, partner by law/tradition/religion/civil union.
- Children: financially dependent biological, adopted, stepchildren, grandchildren.
- Parents: parents and parents-in-law.
- Extended family: grandparents, siblings, siblings-in-law, niblings, cousins, uncles, grand uncles, aunts, grand aunts.

Waiting periods:
- Natural death: 6 months (subject to replacement provisions).
- Accidental death: no waiting period.
- Suicide: 12 months (subject to replacement provisions).

When cover ends:
- Policy cancellation by policyholder or RMA Life.
- Main member death benefit paid and spouse continuation not chosen within 2 months.
- Premium not paid by due date and grace period expires.
- Life absent from South Africa for more than 3 consecutive months.

10) Cancellation, Grace and Lapse
Cooling-off:
- Policyholder can cancel within 31 days of receiving terms and conditions.
- Premiums can be refunded net allowable charges, provided no claim paid.

Grace period:
- Monthly premium frequency: 31 days from due date.
- Annual premium frequency: 45 days from due date.

Notification duty:
- Missed monthly premium: notify within 15 days.
- Missed annual premium: notify within 30 days.

Lapse:
- Policy lapses if two consecutive premiums are missed or two premiums are outstanding.

11) Policy Term and Spouse Continuation
Term:
- All assured lives (except children age rules) are covered for life unless policy terminates.

Children:
- Child cover ends at age 21 unless added as extended family.

Main member death:
- If insured spouse exists, spouse can continue policy and becomes new Main Member.
- RMA Life must be notified within 2 months.
- Spouse receives new premium rating.

Example:
- Original total premium R470 (Main 100 + Spouse 80 + Parent 140 + Parent 150).
- Main member dies, spouse continues.
- Main member premium removed, spouse rerated as main (example rerate to R110).
- New total premium example becomes R400.

12) Reinstatement
- Allowed once in any rolling 24-month period.
- Reinstatement must be requested within 3 months after lapse/cancellation.
- All outstanding premiums must be paid.
- No new waiting period for funeral benefits on reinstatement.
- Outside 3 months, customer must reapply and receives new policy number.

13) Child-specific Events
If a child passes away:
- Example rule: If 1 of 6 children passes away, an additional child can be added at no extra cost.
- Added child has 6-month waiting period.

If child reaches maximum age:
- At age 21 child cover ends under child category.
- Can be moved to extended family if extended family cap not exceeded (max 10 lives).
- No waiting period for this move unless cover amount changes.

14) Allowed Policy Alterations
Cover increase/decrease:
- If cover increases, a 6-month waiting period applies to increased portion.
- No 30-day free cover for increases.

Increase example:
- Existing cover R10 000, premium R100.
- Increase to R30 000, premium becomes R250.
- Added R20 000 portion is under full 6-month waiting period.
- If natural death claim happens before 6 months, only original R10 000 is payable.

Other changes allowed:
- Annual increase option can be changed.
- Nominated beneficiary can be changed once per year.
- Additional lives may be added, within limits:
  1 spouse, 6 children (to age 21), 4 parents, 10 extended family members.
- Additional spouse/children can be under extended family if extended family does not exceed 10 lives.
- Lives can be removed at any time; premium reduces accordingly.

15) General Exclusions
Claims can be excluded for:
- Active participation in war, invasion, hostilities, rebellion, revolution, insurrection, military action.
- Radioactivity, atomic energy, nuclear reaction, terrorism, biological/chemical hazards and warfare agents.
- Drug/narcotic influence unless medically prescribed (not self-prescribed).
- Motor injury while driving over legal alcohol limit, racing, stunt show, speed test.
- Operating/learning aircraft, crew activity, parachuting/falling from aircraft/hot-air balloon (except fare-paying passenger flights).
- Deliberate exposure to exceptional danger (excluding attempts to save human life).
- Criminal acts, attempted illegal acts, incarceration in penal institution.

16) Terms and Conditions: Fraud and Misrepresentation
Fraud:
- RMA can cancel cover and forfeit premiums for fictional claim attempts, fraud, misrepresentation, or non-disclosure.

Misrepresentation:
- Material non-disclosure or incorrect information can lead to application rejection.
- If discovered during policy term or claim stage, contract can be declared null and void from inception.
- Premiums paid may not be refunded.

17) Absence from South Africa
If working outside South Africa:
- Up to 3 consecutive months:
  Cover continues and premiums remain payable.
- More than 3 consecutive months:
  Cover ceases from start of impermissible period.
  No further premiums for that employee/life.
  No benefits payable for insured event in impermissible period.
  Extension only by prior written agreement with insurer.

18) Premium Rules
Premium basis:
- Premium per life depends on age at entry, cover level, and life type.
- Children use a single premium based on selected sum assured.

Premium frequency:
- Monthly or annually.
- Annual premium equals 12 times monthly premium.

Premium payer:
- Policyholder remains responsible, even if another person is mandated to pay.

Payment methods:
- Debit order or stop order for monthly frequency.
- No cash payments.

Missing first premium:
- If first premium is missed, policy start date moves to next month.
- If missed again in second collection month, policy becomes Not Taken Up (NTU) and cancelled from inception.

Premium review communication:
- Policyholder must inform RMA Life within 30 days of changes affecting insured risk.

19) Consent for Disclosure of Personal Information
Policyholder confirms consent from all assured lives for required personal information disclosure.
Insurer may collect/share/process relevant information to:
- Service policy,
- Assess risks,
- Evaluate claims,
- Consider proposals/changes.

Insurer must:
- Process only policy-relevant information,
- Keep information secure and confidential,
- Retain only as long as needed.

Authorised sharing may include:
- Insurer staff and representatives,
- Contracted third parties and subcontractors,
- Reinsurers,
- ASISA-type registers/databases, other insurers/reinsurers for anti-fraud and cost saving,
- Appointed financial adviser or another insurer for product information sharing.

Policyholder rights:
- May request access to collected/processed/shared information.

20) Claims: Core Rules
Beneficiary flow:
- Policyholder nominates beneficiary for main member death benefit.
- If main member and beneficiary both pass away, payment goes to deceased estate.
- For death of other insured lives, payment goes to policyholder (main member).

Currency and payment:
- Claims paid in South African Rand (ZAR).
- Paid only to South African bank accounts.

21) Claim Reporting and Contact
Report claims via nearest RMA Life branch, telephone or email:
- Tel: 0860 222 132
- Email: funeralclaims@randmutual.co.za

Service standard:
- Valid claim can be paid within 48 hours once all required documents are received.

Claim deadline:
- As soon as possible, and within 6 months (180 days) from date of death.

22) Documents Required for Claims
- Completed claim form (branch or contact centre).
- RMA Life Death Notification Form.
- Certified ID copy of deceased.
- Certified ID copy of claimant/beneficiary.
- Certified death certificate from Department of Home Affairs.
- Original/certified DHA1663 (all 4 pages: death/stillbirth notification).
- Original/certified DHA1660 (all 2 pages: notification by traditional leader).
- Proof of claimant bank account (bank stamped).
- Police report for unnatural death.

Important:
- Claims considered only for assured lives listed on membership application form.

23) Claim Settlement and Repudiation
RMA may defer or decline payment until all requirements are met.
Incorrect information may lead to recalculated or declined benefits.
Fraudulent claims may cause immediate policy cancellation, no benefit payment, and no premium refund.

Repudiation means rejection/refusal to pay all or part of a claim.
Claims can be rejected when:
- Event/risk is not covered,
- Event is covered but premiums for that life are unpaid,
- Policy has lapsed,
- Policy conditions are not met.

If rejected:
- Beneficiary receives written decision and reasons.
- Beneficiary has 90 days from repudiation letter to lodge complaint/representation.
- Complaints Officer responds within 6 weeks and may uphold or overturn decision.
- If upheld, beneficiary must be informed about Ombudsman route.

24) Stillbirth and Non-disclosure Notes
Stillbirth claims:
- RMA may repudiate if stillbirth is due to termination of pregnancy.
- Doctor letter confirming gestational age may be required.
- Maximum of 3 stillbirth claims per policyholder for policy duration.
- Additional information may be requested to verify validity.

Non-disclosure/misrepresentation:
- Can trigger rejection or contract voiding from inception with no refund.

25) Unclaimed Benefits
Definition:
- Claim is due but client/beneficiary cannot be traced for payment.

Timeframe:
- Right to unclaimed benefits remains until paid.

Registration:
- After 3 years (36 months) of reasonable but unsuccessful tracing, claim is classified as unclaimed benefit.

Tracing framework:
- RMA follows ASISA Code on Unclaimed Benefits.
- May use external data sources and tracing agents.
- Administrative/tracing costs can be deducted from benefit.
- Such costs may apply after 6 months from date benefit first became due.

26) Complaints and Disputes Process
Customer should submit complaint/dispute to RMA as soon as possible with:
- Full name,
- Claim number,
- Complaint details,
- Supporting documents.

RMA process commitments:
- Acknowledge receipt in writing within 24 hours.
- Keep complainant informed of progress.
- Investigate promptly and communicate outcome.
- Aim to resolve within 6 weeks where required information is available.
- If delayed beyond 6 weeks, provide weekly progress updates.
- Keep complete complaint records as legally required.

Escalation:
- If dissatisfied with response/decision, complaint may be escalated.
- Legal action route exists if unresolved.
- Summons must be served within 180 days after expiry of stated 90-day period.
- Missing legal timelines may forfeit benefits and liability rights.

Sales-process complaint channel:
RMA Compliance Manager
PO Box 61413
Marshalltown
2107

Practical talk-track for JFAs
1. Start with consolidation value:
   "Let's combine your existing funeral covers into one clear plan so your family has less admin and better visibility."
2. Confirm life categories and limits.
3. Explain waiting periods honestly before closing.
4. Explain VAS as support (not cash replacement).
5. Confirm claims documents early so family is prepared.

Field checklist before closing
- Correct life categories and number of lives.
- Cover amounts within policy limits and main member cap.
- Beneficiary details captured correctly.
- Increase option selected and explained.
- Premium frequency and payment method confirmed.
- Waiting periods and exclusions explained.
- POPIA/consent explained and acknowledged.`,
        capital: `Capital Legacy - Complete Deep Dive

Who They Are
Capital Legacy Wills and Estates is a South African financial and legal services business focused on estate planning, wills, trust structures, and deceased estate administration.

Their core purpose is to make sure that when a person dies:
- their assets are protected
- their family receives money quickly
- their estate is wound up efficiently
- there is no unnecessary legal or administrative chaos

They operate in the fiduciary and estate administration space, handling:
- legal administration of assets
- protection of legacy
- execution of wishes after death

They are not only a will-writing company. They position themselves as a turnkey estate solution provider:
planning -> death -> payout -> estate finalisation.

Their Relationship With Matla Life Investments
Matla Life Investments acts as a financial distribution and advisory partner.

In practical terms:
- Matla Life supports clients with financial planning and life insurance solutions
- Capital Legacy provides legal estate structures and estate administration execution

How the partnership works:
- Matla Life: financial advice, life cover structuring, client acquisition and servicing, risk planning
- Capital Legacy: legal and estate execution, estate planning, will drafting, estate admin, trusts and legacy protection

They are separate companies in a strategic partnership model:
- Matla brings the client and financial plan
- Capital Legacy provides the legal estate solution that supports outcomes after death

This creates a full estate and insurance ecosystem.

What Makes Capital Legacy Different
Traditional model in South Africa:
- will drafted by attorney
- death occurs
- family waits 1 to 3 years for final estate outcomes
- executor fees can be high

Capital Legacy's model is designed to:
- reduce delays
- provide immediate liquidity for family
- control executor costs
- bundle services into one structured solution

Their Services - Full Detail
1) Drafting Your Will (Core Foundation Service)
They create a legally valid and professionally structured will designed to:
- handle complex family structures
- protect minor children
- create testamentary trusts at death
- structure asset distribution more efficiently

Result: the will becomes a legal and financial strategy tool.

2) Executor of Your Estate
After death, they can execute:
- reporting to the Master of the High Court
- asset collection and valuation
- debt settlement
- SARS process management
- inheritance distribution

Why this matters:
- avoids delays and conflict when no executor is pre-appointed
- improves process certainty for the family

3) Immediate Cash for Your Family (Liquidity Solution)
Common estate problem:
- bank accounts are frozen
- policy payouts can take time
- estates can take months/years

Capital Legacy structures liquidity planning so family can:
- receive support quickly
- pay funeral costs
- maintain daily living needs

Often linked to life cover planning.

4) Testamentary Trusts (Minor Children and Dependants)
For beneficiaries under 18 or dependants unable to self-manage funds:
- trust activates at death
- inheritance is protected
- payouts are controlled
- misuse risk is reduced

5) Living Trusts (Asset Protection While Alive)
Used to:
- move assets outside personal estate
- protect wealth
- reduce estate-related costs and risks
- improve long-term estate structuring

Capital Legacy assists with trust setup, structuring, and compliance.

6) Estate Administration (Full Post-Death Process)
They manage:
- reporting death to the Master
- creditor notice process
- SARS tax clearance
- property transfer process
- final distributions to heirs

This process can run long; they execute it on behalf of the family.

7) Beneficiary Fund Solutions
Where funds are left to minors or legally incapable beneficiaries:
- funds are managed professionally
- controlled income can be paid out
- capital can remain protected

8) Secure Document Storage
They secure:
- original will
- key legal and estate documents

This reduces common risk:
- will not found
- wrong will used
- intestate outcomes

9) Legacy Protection Plan (Bundled Model)
Typically includes:
- will drafting
- executor appointment
- estate liquidity planning
- trust planning
- administration cost planning

This makes estate planning a structured, pre-funded system instead of a once-off legal event.

How They Make Money
Revenue can come from:
- structured service fees
- estate administration fees
- fiduciary service fees
- partner distribution models

Model objective:
- reduce heavy surprise costs later
- structure and spread costs earlier where possible

The Real Value They Provide
Without planning:
- families can wait years for money
- minors may receive unprotected cash
- estate value is reduced by delays and poor structure
- assets can get stuck in process

With proper Capital Legacy structuring:
- families can receive faster support
- inheritance can be protected
- costs are controlled better
- execution is professional and more predictable

One Powerful Sentence
Capital Legacy is a fiduciary estate planning and administration company that designs, funds, and executes an end-to-end legacy plan so families are financially protected and estates are wound up efficiently after death.`,
        life: `Life Cover - JFA Learning Hub

CHAPTER 1
What Is Life Cover Really? (The Financial & Human Meaning)

1.1 The core definition
Life cover (life insurance) is a financial risk transfer mechanism.
You transfer the financial risk of your death to an insurer.
In exchange for a premium, the insurer promises to pay a lump sum when you die.

1.2 The real problem life cover solves
When a person dies, 4 economic shocks happen immediately:
- Income stops
- Debt remains
- Dependants still need support
- Funeral costs arise

Life cover replaces the economic value of a human life.
Not emotionally, financially.

1.3 Human Life Value (HLV) concept
Your life has a measurable financial value based on:
- Your income
- Years left to work
- Future growth
- Number of dependants

Example:
Age: 30
Income: R20,000/month
Working years left: 35
Future earnings are about R8.4 million+.
That is your economic life value.
Life cover is designed to protect that value.

1.4 Two foundational models of life cover
Individual life cover:
- You own the policy
- You choose the cover amount
- You keep it if you change jobs

Group life cover (like RMA):
- Employer owns the master policy
- Employer sets benefits
- Employees are covered as members

CHAPTER 2
The Mathematics and Structure of Life Cover

2.1 The pricing model (how insurers calculate your premium)
Life cover pricing is based on mortality risk (probability of death by age).
Insurers use mortality tables and consider:
- Age
- Gender
- Health
- Smoking status
- Occupation

Risk logic example:
- A 25-year-old usually has lower probability of death and cheaper premium.
- A 55-year-old usually has higher probability and higher premium.

2.2 The 3 components of a life premium
Premium has three main components:
1) Cost of insurance (pure risk cost)
2) Expenses (admin, commission, operations)
3) Profit margin

2.3 Types of life cover structures
Level cover:
- Cover amount stays the same
- Premium usually increases over time

Increasing cover:
- Cover grows with inflation
- Protects real value over time

Decreasing cover:
- Common for home loans/business loans
- Debt reduces over time, so cover can reduce

2.4 The payout mechanics
When death occurs:
- Claim is submitted
- Documents are provided (death certificate, IDs, beneficiary details)
- Insurer validates the claim
- Lump sum is paid (generally tax-free in South Africa context)

2.5 Why payout is a lump sum
Because funds may need to:
- Settle debts immediately
- Generate income for dependants
- Pay for education
- Fund long-term living costs

It acts as a capital replacement fund.

CHAPTER 3
RMA LIFE COVER - Deep Technical Structure

3.1 Group risk pool concept
In RMA, many workers are insured together.
This creates:
- Shared risk
- Lower cost
- Broader access

This is collective underwriting:
RMA underwrites the workforce risk pool, not each person the same way as retail individual cover.

3.2 How life cover amount is determined
Many RMA schemes use a salary multiple formula, for example:
- 2 x annual salary
- 3 x annual salary
- 5 x annual salary

Example:
Monthly salary = R18,000
Annual salary = R216,000
At 3x, life cover = R648,000

Salary-based cover links directly to income replacement capacity.

3.3 Who pays for the cover?
Operationally, employer pays premiums to RMA.
Economically, it is part of employee total cost to company.

3.4 Underwriting advantage
Individual life cover can require medical evidence.
RMA group life often gives automatic cover up to a Free Cover Limit (FCL).
Example:
- First R500,000 may be covered without medicals
- Amount above FCL may require medical underwriting

3.5 What happens when leaving employment?
Group life cover generally stops when employment ends.
Some schemes allow continuation options if action is taken in time.

3.6 Why group cover may be insufficient on its own
Example:
- Salary: R240,000/year
- Group cover: 3x = R720,000
- Full economic value may be far higher

So group cover is often a base layer, not complete protection.

3.7 Beneficiary system
Members should complete a nomination form.
If no nomination exists, distribution may follow dependency/legal processes, which can delay payout.

MASTER SUMMARY
Life cover is not only about death, it is about:
- Replacing income
- Protecting dependants
- Preserving dignity
- Reducing long-term financial hardship

In RMA context, life cover is:
- Salary-linked capital replacement
- Employer-sponsored
- Cost-efficient via group risk pooling

Important: it may still need to be complemented by broader personal financial planning.`,
        matla: `Product Knowledge - Matla Plan

Matla Life Plan - Sales Journey
Source base: "Matla Life Plan - Sales Journey-2.pptx"
This training expands the slide flow into a practical field guide.

1) Big Picture: What this journey is for
The Matla Plan flow is designed to make sure:
- The client is captured correctly,
- Cover is selected correctly,
- Affordability is respected,
- Beneficiaries are confirmed,
- Signature and location are captured,
- Policy is issued cleanly with minimal errors.

Why this matters:
- Better client experience.
- Fewer policy failures and reversals.
- Cleaner admin for verification and claims.
- Stronger trust in the consultant and brand.

2) Step 1 - Complete Policy Holder Details
Slide anchor: "Complete Policy holder details"

What to do:
- Capture policyholder personal details exactly as on official ID.
- Verify contact details (phone + alternate if available).
- Confirm deduction account details and date expectations.

Critical system behavior:
- The system may indicate an existing policy.

Mandatory consultant action:
- If an existing policy is flagged, explain clearly that a second deduction may occur if a second policy is activated.
- Client must understand this before proceeding.

Talk-track:
"The system shows an existing policy record. If we activate this one as well, you may have two deductions. Let's confirm what you want so there are no surprises."

3) Step 2 - Select Cover (Matla Life Plan)
Slide anchor: "Matla Life Plan - Selecting Cover"

Rules to respect:
- Policyholder must always be covered first.
- You cannot sell family benefit without policyholder cover.
- Add lives assured only after main policyholder cover is valid.

Execution checklist:
- Start with policyholder cover.
- Add spouse/dependants where relevant.
- Confirm each life category and benefit amount.
- Recheck totals before moving forward.

Common error to avoid:
- Trying to structure family-only cover without main member cover.

4) Step 2A - Affordability Gate
Slide anchor: "Check Affordability before you can continue... Even when client does not afford"

What this means:
- Affordability is not optional.
- You should still complete a proper quote flow even if affordability initially fails, because the client may be serviced later.

Best practice:
- Explain affordability result in plain language.
- Keep the quote record complete and compliant.
- Set expectation on next steps (rework/revisit).

Talk-track:
"Right now affordability is not passing. We can still keep this structured so we can revisit once your affordability changes or after we optimize your setup."

5) Step 3 - Select Beneficiaries
Slide anchors:
- "Selecting Beneficiaries"
- "Save and confirm contact details"

What to do:
- Capture beneficiary(ies) accurately.
- Save and verify all beneficiary contact details.
- Confirm relationship to policyholder.
- Confirm who receives what in practical terms.

Quality control:
- Read details back to client before confirming.
- Avoid spelling/ID errors that can delay claims.

6) Step 3A - Confirmation Handling
Slide anchor: "Confirm no longer accepts the policy"

Scenario:
- Client changes mind or does not accept at confirmation.

What to do:
- Do not force close.
- Capture status cleanly as not accepted.
- Save notes for follow-up and objection handling.

Advisor standard:
- Protect trust first; a clean "not now" can become a future "yes".

7) Step 4 - New Business Application
Slide anchors:
- "Your New Policy Number"
- "Confirm that all details are correct"
- "Final Check"

What to do:
- Generate/confirm new policy number.
- Perform full final verification with client:
  identity, cover, lives assured, beneficiaries, deduction details, contact details.
- Do a full final check before signature.

Final-check framework:
- Is the right person insured as policyholder?
- Are all cover values correct?
- Are beneficiary details complete?
- Is affordability outcome understood?
- Is payment timing understood?

8) Signature and Location Capture
Slide anchors:
- "System Captures Client Signature"
- "Complete location that the client signed at"

Non-negotiables:
- Signature must be captured through the system.
- Signing location must be captured correctly.

Why:
- Compliance and audit trail.
- Protects both client and business.

Do not:
- Backdate or misstate location.
- Skip signature quality checks.

9) Plan Submission and Issuing
Slide anchors:
- "Plan Submission submits and issues the policy if affordability is passed"

Rule:
- Issuance happens when submission is complete and affordability passes.

Before pressing submit:
- Confirm no pending corrections.
- Confirm client consent and understanding.
- Confirm capture completeness.

After submit:
- Confirm issued status.
- Confirm policy number with client.
- Set next communication step.

10) If Affordability Fails
Slide anchors:
- "What if my policy fails affordability?"
- "We have you covered"

Recovery pathway:
- Keep the quote and signed process trail where applicable.
- Return later to reassess affordability.
- Re-run the flow and issue once criteria are met.

Business benefit:
- Prevents losing warm clients just because timing was wrong.

11) Consolidation then Return
Slide anchor:
- "What if I want to do consolidation and then come back afterwards?"

Operational approach:
- Handle consolidation first where it improves affordability/value.
- Re-open policy application journey afterwards.
- Re-check affordability and complete issuance.

Talk-track:
"Let's optimize your existing setup first, then we come back and finalize this plan from a stronger position."

12) Revisit Flow for Previously Non-Affording Client
Slide anchors:
- "You can now go back to clients that initially didn't afford..."
- "Simply go through these steps again"

Revisit SOP:
1. Open existing policy application/quote trail.
2. Validate if client circumstances changed.
3. Re-check affordability.
4. Re-confirm all captured data.
5. Re-capture consent where needed.
6. Submit and issue if passed.

13) Express Will Stage
Slide anchors:
- "Express will..." (multiple slides)

Field interpretation:
- There is an additional express-will component in the journey.
- Treat it as an add-on process that must be explained clearly.

When handling this stage:
- Explain purpose and value in simple language.
- Confirm client understanding before acceptance.
- Capture choices and consent accurately.

14) Compliance and Quality Guardrails
Always do:
- Tell the truth about deductions and existing policy impacts.
- Keep affordability transparent.
- Capture signature and location properly.
- Confirm all details before submission.
- Document client decision status clearly.

Never do:
- Hide second deduction implications.
- Push through when client does not accept.
- Skip final check.
- Submit with known data errors.

15) Consultant Performance Scorecard for Matla Plan
Use this to improve consistency:
- Data quality score (errors found post-submit).
- Affordability pass rate.
- Issuance conversion rate.
- Revisit conversion (failed -> issued later).
- Complaint-free cases.

16) Objection Handling (Quick Bank)
"I already have cover."
- "That's valid. Let's compare value and structure so you only keep what truly serves you."

"I can't afford now."
- "No problem. We'll keep this properly prepared and revisit when affordability improves."

"Why all these details?"
- "Because correct details protect your family at claim stage and prevent delays."

17) Closing Script (High-Integrity Close)
"Let's do a final check together: your details, cover, beneficiaries, and deductions are all confirmed. If you're happy, we capture your signature and submit so your policy can be issued correctly."

18) One-line Principle
Matla Plan success is not just about selling a policy; it's about issuing the right policy, correctly, with full client understanding and clean compliance evidence.`
    };
    return content[key] || '';
}

function toggleQuickActions() {
    const menu = document.getElementById('quickActionsMenu');
    if (!menu) return;
    renderQuickActionsMenu();
    const trigger = document.querySelector('.quick-actions-toggle');
    if (trigger) {
        trigger.classList.remove('is-clicked');
        void trigger.offsetWidth;
        trigger.classList.add('is-clicked');
        setTimeout(() => trigger.classList.remove('is-clicked'), 260);
    }
    const nextOpen = !menu.classList.contains('is-open');
    menu.classList.toggle('is-open', nextOpen);
    if (trigger) {
        trigger.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
    }
    if (nextOpen) {
        requestAnimationFrame(() => {
            document.addEventListener('click', handleQuickActionsOutsideClick, true);
        });
    } else {
        document.removeEventListener('click', handleQuickActionsOutsideClick, true);
    }
}

function triggerConfetti() {
    const container = document.getElementById('confetti-container');
    if (!container) return;
    container.innerHTML = '';
    const colors = ['#17A2A4', '#0B2E52', '#7AD9D4', '#103B6B'];
    const count = 32;
    for (let i = 0; i < count; i++) {
        const confetti = document.createElement('span');
        confetti.className = 'confetti';
        confetti.style.left = `${Math.random() * 100}%`;
        confetti.style.background = colors[i % colors.length];
        confetti.style.animationDelay = `${Math.random() * 0.3}s`;
        confetti.style.transform = `translateY(-10vh) rotate(${Math.random() * 360}deg)`;
        container.appendChild(confetti);
    }
    setTimeout(() => {
        container.innerHTML = '';
    }, 2200);
}

function updateSummary() {
    if (ensureDailyContextFresh()) return;
    const today = todayKey();
    const todayRecords = getScopedRecords().filter((r) => recordDateKey(r) === today);
    const totalRegistrations = todayRecords.length;
    const totalForms = getScopedConsentFormsTotalForRange(getStartOfDay(new Date()), new Date());
    const productiveCount = todayRecords.filter((r) => r.productive === 'YES').length;
    const productiveRate = totalRegistrations ? Math.round((productiveCount / totalRegistrations) * 100) : 0;

    const regEl = document.getElementById('summaryRegistrations');
    animateCount(regEl, totalRegistrations, '');
    const formsEl = document.getElementById('summaryForms');
    animateCount(formsEl, totalForms, '');
    const prodEl = document.getElementById('summaryProductive');
    if (prodEl) prodEl.textContent = `${productiveRate}%`;
    if (isPageActive('stats-page')) {
        updateTargetsAndLeaders(todayRecords);
    }
    updateHeroSummary();
    updateCoverageByArea();
    updateAlertPanel();
}

function getArchives() {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.archives)) || [];
}

function renderArchives() {
    const select = document.getElementById('archiveSelect');
    const summary = document.getElementById('archiveSummary');
    const weeklyTeamEl = document.getElementById('archiveWeeklyTeamLeaderboard');
    const monthlyTeamEl = document.getElementById('archiveMonthlyTeamLeaderboard');
    const table = document.getElementById('archiveTable');
    if (!select || !summary || !table) return;

    const scopeEl = document.getElementById('archivesScope');
    if (scopeEl) {
        const label = adminRole === 'ADMIN' ? 'Admin (All)' : adminRole === 'TEAM' ? adminTeam : 'Personal';
        const className = adminRole === 'ADMIN' ? 'admin' : adminRole === 'TEAM' ? 'team' : 'personal';
        scopeEl.innerHTML = `<span class="scope-badge ${className}">Scope: ${label || 'Personal'}</span>`;
    }

    const archives = getArchives();
    const updatedEl = document.getElementById('archivesLastUpdated');
    if (updatedEl) {
        updatedEl.textContent = new Date().toLocaleString('en-ZA');
    }
    select.innerHTML = '';

    if (!archives.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No archives available';
        select.appendChild(opt);
        summary.innerHTML = '<p class="no-data">No archives available.</p>';
        if (weeklyTeamEl) weeklyTeamEl.innerHTML = '<p class="no-data">No data.</p>';
        if (monthlyTeamEl) monthlyTeamEl.innerHTML = '<p class="no-data">No data.</p>';
        table.innerHTML = '<p class="no-data">No data.</p>';
        return;
    }

    const sorted = [...archives].sort((a, b) => b.date.localeCompare(a.date));
    sorted.forEach((archive) => {
        const opt = document.createElement('option');
        opt.value = archive.date;
        opt.textContent = `${archive.date} (${archive.reason})`;
        select.appendChild(opt);
    });

    select.onchange = () => renderArchiveDetail(select.value);
    renderArchiveDetail(select.value || sorted[0].date);
}

function renderArchiveDetail(dateKey) {
    const summary = document.getElementById('archiveSummary');
    const topTeamEl = document.getElementById('archiveTopTeam');
    const teamLeaderboardEl = document.getElementById('archiveTeamLeaderboard');
    const weeklyTeamEl = document.getElementById('archiveWeeklyTeamLeaderboard');
    const monthlyTeamEl = document.getElementById('archiveMonthlyTeamLeaderboard');
    const table = document.getElementById('archiveTable');
    if (!summary || !table) return;

    const archives = getArchives();
    const archive = archives.find((a) => a.date === dateKey) || archives[archives.length - 1];
    if (!archive) return;

    const records = (archive.records || []).filter(recordMatchesScope);
    const totalForms = records.reduce((sum, r) => sum + (r.consentForms || 0), 0);
    const productiveCount = records.filter((r) => r.productive === 'YES').length;
    const productiveRate = records.length ? Math.round((productiveCount / records.length) * 100) : 0;
    const topTeamResult = topBy(records, (r) => r.team);

    summary.innerHTML = `
        <div class="summary-card">
            <div class="summary-title">Archive Summary (${escapeHtml(archive.date)})</div>
            <div class="summary-grid">
                <div class="summary-item">
                    <span class="summary-value">${records.length}</span>
                    <span class="summary-label">Registrations</span>
                </div>
                <div class="summary-item">
                    <span class="summary-value">${totalForms}</span>
                    <span class="summary-label">Consent Forms</span>
                </div>
                <div class="summary-item">
                    <span class="summary-value">${productiveRate}%</span>
                    <span class="summary-label">Productive Rate</span>
                </div>
            </div>
        </div>
    `;

    if (topTeamResult && topTeamEl) {
        topTeamEl.innerHTML = `
                <div class="summary-card">
                    <div class="summary-title">Top Team of the Day</div>
                    <div class="summary-grid">
                        <div class="summary-item">
                            <span class="summary-value">${escapeHtml(topTeamResult.name)}</span>
                            <span class="summary-label">${topTeamResult.value} Consent Forms</span>
                        </div>
                    </div>
                </div>
            `;
    }

    if (teamLeaderboardEl) {
        teamLeaderboardEl.innerHTML = `
            <div class="summary-card">
                <div class="summary-title">Team Leaderboard</div>
                <div class="mini-table">${renderLeaderboardTable(records, (r) => r.team, 'Team', 5)}</div>
            </div>
        `;
    }

    if (weeklyTeamEl) {
        const weekRange = getArchiveWeekRange(dateKey);
        const weekRecords = getArchiveRangeRecords(weekRange.start, weekRange.end);
        weeklyTeamEl.innerHTML = `
            <div class="summary-card">
                <div class="summary-title">Team Leaderboard (Week)</div>
                <div class="mini-table">${renderLeaderboardTable(weekRecords, (r) => r.team, 'Team', 5)}</div>
            </div>
        `;
    }

    if (monthlyTeamEl) {
        const monthRange = getArchiveMonthRange(dateKey);
        const monthRecords = getArchiveRangeRecords(monthRange.start, monthRange.end);
        monthlyTeamEl.innerHTML = `
            <div class="summary-card">
                <div class="summary-title">Team Leaderboard (Month)</div>
                <div class="mini-table">${renderLeaderboardTable(monthRecords, (r) => r.team, 'Team', 5)}</div>
            </div>
        `;
    }

    if (!records.length) {
        table.innerHTML = '<p class="no-data">No records for this day.</p>';
        return;
    }

    const sortedByForms = [...records].sort((a, b) => (b.consentForms || 0) - (a.consentForms || 0));
    let tableHTML = `
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Name</th>
                    <th>Team</th>
                    <th>Consent Forms</th>
                    <th>Facility</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
`;

    sortedByForms.forEach((record, index) => {
        const rankClass = index < 3 ? `rank-${index + 1}` : '';
        const rankBadge = `<span class="rank-badge ${rankClass}">#${index + 1}</span>`;
        const productiveIcon = record.productive === 'YES' ? '✓' : '✗';
        const targetMet = (record.consentForms || 0) >= 2;
        const targetBadge = `<span class="target-badge ${targetMet ? 'met' : 'missed'}">${targetMet ? 'Target Met' : 'Below Target'}</span>`;
        tableHTML += `
            <tr>
                <td>${rankBadge}</td>
                <td><strong>${escapeHtml(record.name)}</strong></td>
                <td>${escapeHtml(record.team || '—')}</td>
                <td><strong>${record.consentForms || 0}</strong></td>
                <td>${escapeHtml(record.facility?.name ?? '')}</td>
                <td>${productiveIcon} ${record.productive === 'YES' ? 'Productive' : 'Not Productive'} ${targetBadge}</td>
            </tr>
        `;
    });

    tableHTML += '</tbody></table>';
    table.innerHTML = tableHTML;
}

function exportSelectedArchiveCsv() {
    const select = document.getElementById('archiveSelect');
    if (!select || !select.value) {
        showToast('Select an archive first.', 'error');
        return;
    }
    if (!hasAppPermission('forms')) {
        showToast('You do not have access to export archives.', 'error');
        return;
    }
    const archives = getArchives();
    const archive = archives.find((a) => a.date === select.value);
    if (!archive) {
        showToast('Archive not found.', 'error');
        return;
    }
    const records = (archive.records || []).filter(recordMatchesScope);
    exportRecordsCsv(records, `jfa-archive-${archive.date}.csv`);
    logAudit('Exported archive', `Archive: ${archive.date} • Rows: ${records.length}`);
    logExportHistory(`Archive Export: ${archive.date}`, records.length);
}

function exportAllArchivesCsv() {
    const archives = getArchives();
    if (!archives.length) {
        showToast('No archives to export.', 'error');
        return;
    }
    if (!canExportFromCurrentScope()) {
        showToast('You do not have access to export archives.', 'error');
        return;
    }
    const allRecords = archives.flatMap((a) => a.records || []).filter(recordMatchesScope);
    exportRecordsCsv(allRecords, 'jfa-archives-all.csv');
    logAudit('Exported archives', `Rows: ${allRecords.length}`);
    logExportHistory('Archives Export (All)', allRecords.length);
}

const EXPORT_BRAND_NAME = 'Matla Life Daily Ops';
const EXPORT_LOGO_FILE = 'matla-life-logo2.png';
let exportLogoDataUrlCache = '';

function csvCell(value) {
    const raw = value == null ? '' : String(value);
    const flattened = raw
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .replace(/\t/g, ' ')
        .replace(/\n+/g, ' | ')
        .replace(/\s+/g, ' ')
        .trim();
    const safe = /^[=+\-@]/.test(flattened) ? `'${flattened}` : flattened;
    return `"${safe.replace(/"/g, '""')}"`;
}

function normalizeCsvValue(value) {
    if (value == null) return '';
    if (value instanceof Date && Number.isFinite(value.getTime())) {
        return value.toLocaleString('en-ZA');
    }
    if (typeof value === 'boolean') {
        return value ? 'Yes' : 'No';
    }
    if (Array.isArray(value)) {
        return value.map((item) => normalizeCsvValue(item)).filter(Boolean).join(' | ');
    }
    if (typeof value === 'object') {
        try {
            return JSON.stringify(value);
        } catch (_) {
            return String(value);
        }
    }
    return String(value);
}

function buildCsvRowLine(values, width) {
    const safeWidth = Math.max(0, Number(width) || 0);
    const source = Array.isArray(values) ? values : [];
    const cells = [];
    for (let i = 0; i < safeWidth; i += 1) {
        cells.push(csvCell(normalizeCsvValue(source[i])));
    }
    return cells.join(',');
}

function buildBrandedCsv(reportLabel, headers, rows, exportReason = '') {
    const generatedAt = new Date().toLocaleString('en-ZA');
    const exportedBy = formatJfaName(appUser || 'Unknown user');
    const logoUrl = new URL(EXPORT_LOGO_FILE, window.location.href).href;
    const safeHeaders = Array.isArray(headers) ? headers : [];
    const safeRows = Array.isArray(rows) ? rows : [];
    const lines = [];
    lines.push(buildCsvRowLine(['Brand', EXPORT_BRAND_NAME], 2));
    lines.push(buildCsvRowLine(['Logo', logoUrl], 2));
    lines.push(buildCsvRowLine(['Report', reportLabel || 'Data Export'], 2));
    lines.push(buildCsvRowLine(['Generated At', generatedAt], 2));
    lines.push(buildCsvRowLine(['Exported By', exportedBy], 2));
    if (exportReason) {
        lines.push(buildCsvRowLine(['Export Reason', exportReason], 2));
    }
    lines.push(buildCsvRowLine(['Total Rows', safeRows.length], 2));
    lines.push('');
    lines.push(buildCsvRowLine(safeHeaders, safeHeaders.length));
    safeRows.forEach((row) => {
        lines.push(buildCsvRowLine(row, safeHeaders.length));
    });
    return lines.join('\r\n');
}

function downloadCsvContent(content, filename) {
    const safeName = String(filename || 'matla-export.csv').replace(/\.(html|txt)$/i, '.csv');
    const blob = new Blob([`\uFEFF${content}`], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = safeName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function exportRecordsCsv(records, filename) {
    if (!records.length) {
        showToast('No data to export for this day.', 'error');
        return;
    }
    const headers = [
        'Name',
        'Phone',
        'Team',
        'Facility',
        'Facility Type',
        'Area',
        'Contact',
        'Phone (Facility)',
        'Consent Forms',
        'Productive',
        'Timestamp'
    ];
    const rows = records.map((record) => [
        record.name,
        record.phone,
        record.team,
        record.facility?.name ?? '',
        record.facility?.type ?? '',
        record.facility?.area ?? '',
        record.facility?.contact ?? '',
        record.facility?.phone ?? '',
        record.consentForms ?? 0,
        record.productive ?? '',
        record.timestamp ?? ''
    ]);
    exportCsvWithHeaders(headers, rows, filename, 'Records Export');
}

function exportRecordsPdf(records, filename) {
    if (!records.length) {
        showToast('No data to export for this day.', 'error');
        return;
    }
    const headers = [
        'Name',
        'Phone',
        'Team',
        'Facility',
        'Facility Type',
        'Area',
        'Contact',
        'Phone (Facility)',
        'Consent Forms',
        'Productive',
        'Timestamp'
    ];
    const rows = records.map((record) => [
        record.name,
        record.phone,
        record.team,
        record.facility?.name ?? '',
        record.facility?.type ?? '',
        record.facility?.area ?? '',
        record.facility?.contact ?? '',
        record.facility?.phone ?? '',
        record.consentForms ?? 0,
        record.productive ?? '',
        record.timestamp ?? ''
    ]);
    exportPdfWithHeaders(headers, rows, filename, 'Records Export');
}

function exportCsvWithHeaders(headers, rows, filename, reportLabel = 'Data Export') {
    const reason = requestExportReason(reportLabel, () => exportCsvWithHeaders(headers, rows, filename, reportLabel));
    if (!reason) return false;
    const content = buildBrandedCsv(reportLabel, headers, rows, reason);
    downloadCsvContent(content, filename);
    showToast(`Exported ${reportLabel} as branded CSV.`, 'success');
    return true;
}

async function preloadExportLogoDataUrl() {
    if (exportLogoDataUrlCache) return exportLogoDataUrlCache;
    try {
        const response = await fetch(new URL(EXPORT_LOGO_FILE, window.location.href).href, { cache: 'force-cache' });
        if (!response.ok) return '';
        const blob = await response.blob();
        const dataUrl = await new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result || ''));
            reader.onerror = () => resolve('');
            reader.readAsDataURL(blob);
        });
        exportLogoDataUrlCache = String(dataUrl || '');
        return exportLogoDataUrlCache;
    } catch (_) {
        return '';
    }
}

function getExportPdfLogoSrc() {
    return exportLogoDataUrlCache || new URL(EXPORT_LOGO_FILE, window.location.href).href;
}

function exportPdfWithHeaders(headers, rows, filename, reportLabel = 'Data Export') {
    const reason = requestExportReason(reportLabel, () => exportPdfWithHeaders(headers, rows, filename, reportLabel));
    if (!reason) return false;
    const safeHeaders = Array.isArray(headers) ? headers : [];
    const safeRows = Array.isArray(rows) ? rows : [];
    const printOrientation = safeHeaders.length > 7 ? 'landscape' : 'portrait';
    const logoSrc = getExportPdfLogoSrc();
    const generatedAt = new Date().toLocaleString('en-ZA');
    const exportedBy = formatJfaName(appUser || 'Unknown user');
    const title = `${reportLabel} | ${EXPORT_BRAND_NAME}`;
    const safeTitle = String(title).replace(/[<>&"]/g, '');
    const tableHead = safeHeaders.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
    const normalizedRows = safeRows.map((row) => {
        const source = Array.isArray(row) ? row : [row];
        const cells = [];
        for (let i = 0; i < safeHeaders.length; i += 1) {
            cells.push(normalizeCsvValue(source[i] ?? ''));
        }
        return cells;
    });
    const tableBody = normalizedRows.map((row) => {
        const cells = row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join('');
        return `<tr>${cells}</tr>`;
    }).join('');
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${safeTitle}</title>
  <style>
    @page { size: A4 ${printOrientation}; margin: 12mm; }
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 20px; color: #111827; background: #f7f8fb; }
    .report-shell { max-width: 1200px; margin: 0 auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 14px; padding: 20px; }
    .report-header { position: relative; min-height: 84px; margin-bottom: 14px; border-bottom: 1px solid #e5e7eb; padding-bottom: 12px; padding-right: 108px; }
    .report-title { margin: 0; font-size: 1.45rem; letter-spacing: 0.2px; color: #0f172a; }
    .report-meta { margin-top: 8px; color: #374151; font-size: 0.92rem; }
    .report-logo { position: absolute; top: 0; right: 0; width: 88px; height: 88px; object-fit: contain; }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; }
    th, td { border: 1px solid #e5e7eb; padding: 10px; text-align: left; font-size: 0.9rem; vertical-align: top; }
    th { background: #f3f4f6; color: #111827; font-weight: 700; }
    tr:nth-child(even) td { background: #fafafa; }
    .empty { margin-top: 16px; color: #6b7280; }
    @media print {
      body { background: #fff; margin: 0; }
      .report-shell { border: 0; border-radius: 0; padding: 0; max-width: none; }
      .report-logo { position: fixed; top: 0; right: 0; width: 26mm; height: 26mm; }
      .report-header { padding-right: 32mm; }
    }
  </style>
</head>
<body>
  <div class="report-shell">
    <header class="report-header">
      <h1 class="report-title">${escapeHtml(reportLabel)}</h1>
      <div class="report-meta">Generated: ${escapeHtml(generatedAt)}<br>Exported by: ${escapeHtml(exportedBy)}<br>Reason: ${escapeHtml(reason)}<br>Total rows: ${safeRows.length}</div>
      <img class="report-logo" src="${escapeHtml(logoSrc)}" alt="Matla Life logo">
    </header>
    ${normalizedRows.length ? `<table><thead><tr>${tableHead}</tr></thead><tbody>${tableBody}</tbody></table>` : '<p class="empty">No records available for this export.</p>'}
  </div>
  <script>window.onload = function(){ setTimeout(function(){ window.print(); }, 160); };</script>
</body>
</html>`;
    const win = window.open('', '_blank', 'noopener,noreferrer');
    if (!win) {
        showToast('Pop-up blocked. Allow pop-ups to export PDF.', 'error');
        return false;
    }
    win.document.open();
    win.document.write(html);
    win.document.close();
    showToast(`Opened ${reportLabel} PDF view. Save as PDF from print dialog.`, 'success');
    return true;
}

function openExportReasonModal(reportLabel, retryFn) {
    const modal = document.getElementById('export-reason-modal');
    const titleEl = document.getElementById('exportReasonTitle');
    const promptEl = document.getElementById('exportReasonPrompt');
    const inputEl = document.getElementById('exportReasonInput');
    const errorEl = document.getElementById('exportReasonError');
    if (!modal || !promptEl || !inputEl) {
        showToast('Export reason prompt is unavailable right now.', 'error');
        return;
    }
    pendingExportReasonLabel = String(reportLabel || 'Export');
    pendingExportRetry = typeof retryFn === 'function' ? retryFn : null;
    exportFlowPending = true;
    exportFlowCanceled = false;
    if (titleEl) titleEl.textContent = `${pendingExportReasonLabel} • Export Reason`;
    if (promptEl) {
        promptEl.textContent = `Export reason for "${pendingExportReasonLabel}" (minimum 5 characters):`;
    }
    inputEl.value = '';
    if (errorEl) {
        errorEl.textContent = '';
        errorEl.style.display = 'none';
    }
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
    setTimeout(() => inputEl.focus(), 20);
}

function closeExportReasonModal(cancel = false) {
    const modal = document.getElementById('export-reason-modal');
    const errorEl = document.getElementById('exportReasonError');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
    if (errorEl) {
        errorEl.textContent = '';
        errorEl.style.display = 'none';
    }
    if (cancel) {
        exportFlowPending = false;
        exportFlowCanceled = true;
        pendingExportReasonLabel = '';
        pendingExportReasonValue = '';
        pendingExportRetry = null;
        showToast('Export canceled.', 'error');
    }
}

function submitExportReasonModal() {
    const inputEl = document.getElementById('exportReasonInput');
    const errorEl = document.getElementById('exportReasonError');
    const reason = String(inputEl?.value || '').trim();
    if (!reason) {
        if (errorEl) {
            errorEl.textContent = 'Export reason is required.';
            errorEl.style.display = 'block';
        }
        return;
    }
    if (reason.length < 5) {
        if (errorEl) {
            errorEl.textContent = 'Export reason must be at least 5 characters.';
            errorEl.style.display = 'block';
        }
        return;
    }
    pendingExportReasonValue = reason;
    exportFlowPending = false;
    exportFlowCanceled = false;
    const retry = pendingExportRetry;
    closeExportReasonModal(false);
    pendingExportRetry = null;
    if (typeof retry === 'function') {
        setTimeout(() => retry(), 0);
    }
}

function requestExportReason(reportLabel = 'Export', retryFn = null) {
    const normalizedLabel = String(reportLabel || 'Export');
    if (pendingExportReasonValue && pendingExportReasonLabel === normalizedLabel) {
        const reason = pendingExportReasonValue;
        pendingExportReasonValue = '';
        pendingExportReasonLabel = '';
        exportFlowPending = false;
        exportFlowCanceled = false;
        return reason;
    }
    openExportReasonModal(normalizedLabel, retryFn);
    return '';
}

function exportBrandedReport(headers, rows, filename, reportLabel = 'Export') {
    exportCsvWithHeaders(headers, rows, filename, reportLabel);
}

// Update statistics
function updateStatistics() {
    const scopedRecords = getScopedRecords();
    updateDashboardVisibility();
    const now = new Date();
    const todayStart = getStartOfDay(now);
    const weekStart = getStartOfWeek(now);
    const monthStart = getStartOfMonth(now);
    const scopedLeadsAll = getScopedLeadsInRange(new Date(2000, 0, 1), now);

    if (scopedRecords.length === 0 && scopedLeadsAll.length === 0) {
        updateTargetsAndLeaders([]);
        const identity = adminRole === 'PERSONAL' ? getLeadIdentity() : null;
        if (identity?.name) {
            const dailyMine = getScopedConsentFormsTotalForRange(todayStart, now);
            const weeklyMine = getScopedConsentFormsTotalForRange(weekStart, now);
            const monthlyMine = getScopedConsentFormsTotalForRange(monthStart, now);
            const topPerformerDiv = document.getElementById('topPerformer');
            if (topPerformerDiv) {
                topPerformerDiv.innerHTML = `
                    <div class="performer-avatar">0</div>
                    <h3>${escapeHtml(formatJfaName(identity.name))}</h3>
                    <p>${dailyMine} Consent Forms Today</p>
                    <p style="font-size: 1rem; opacity: 0.9;">${escapeHtml(identity.team || '—')}</p>
                    <p style="font-size: 0.9rem; opacity: 0.85;">Week: ${weeklyMine} • Month: ${monthlyMine}</p>
                `;
            }
            const rankingsDiv = document.getElementById('individualRankings');
            if (rankingsDiv) {
                rankingsDiv.innerHTML = `
                    <table>
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>Name</th>
                                <th>Team</th>
                                <th>Consent Forms</th>
                                <th>Facility</th>
                                <th>Month Total</th>
                                <th>Status</th>
                                <th>Productivity</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>1</td>
                                <td><strong>${escapeHtml(formatJfaName(identity.name))}</strong></td>
                                <td>${escapeHtml(identity.team || '—')}</td>
                                <td><strong>${dailyMine}</strong></td>
                                <td>—</td>
                                <td>${monthlyMine} (0%)</td>
                                <td><span class="status-pill status-pending">Building</span></td>
                                <td>Not Productive</td>
                            </tr>
                        </tbody>
                    </table>
                `;
            }
        }
        const topPerformerDiv = document.getElementById('topPerformer');
        if (topPerformerDiv && !(adminRole === 'PERSONAL' && getLeadIdentity()?.name)) {
            topPerformerDiv.innerHTML = '<p class="no-data">No submissions yet today</p>';
        }
        const teamStatsDiv = document.getElementById('teamStats');
        if (teamStatsDiv) {
            teamStatsDiv.innerHTML = '<p class="no-data">No team data available</p>';
        }
        const facilityStatsDiv = document.getElementById('facilityStats');
        if (facilityStatsDiv) {
            facilityStatsDiv.innerHTML = '<p class="no-data">No facility data available yet</p>';
        }
        const rankingsDiv = document.getElementById('individualRankings');
        if (rankingsDiv && !(adminRole === 'PERSONAL' && getLeadIdentity()?.name)) {
            rankingsDiv.innerHTML = '<p class="no-data">No rankings available yet</p>';
        }
        updateCoverageByArea();
        updateAlertPanel();
        renderTeamHeatmap();
        renderFacilityForecast();
        renderAuditLog();
        renderAttendancePanel();
        renderTeamTrendChart();
        return;
    }

    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, now),
        ...scopedRecords.filter((r) => r.timestamp)
    ];
    const monthTotals = new Map();
    monthRecords.forEach((r) => {
        if (!r.name) return;
        const key = normalizeJfaName(r.name);
        const existing = monthTotals.get(key) || { name: formatJfaName(r.name), forms: 0 };
        existing.forms += r.consentForms || 0;
        monthTotals.set(key, existing);
    });
    const monthLeads = getScopedLeadsInRange(monthStart, now);
    const monthLeadTotals = buildScopedLeadTotalsMap(monthLeads);
    monthLeadTotals.forEach((entry, key) => {
        if (monthTotals.has(key)) return;
        monthTotals.set(key, { name: entry.name, forms: entry.consentForms });
    });

    updateTargetsAndLeaders(scopedRecords);

    // Top Individual Performer
    const aggregated = [];
    const aggMap = new Map();
    scopedRecords.forEach((r) => {
        if (!r.name) return;
        const key = normalizeJfaName(r.name);
        if (!key) return;
        const existing = aggMap.get(key) || { name: formatJfaName(r.name), team: r.team, consentForms: 0, productive: false, facility: r.facility };
        existing.consentForms += r.consentForms || 0;
        if (r.productive === 'YES') existing.productive = true;
        existing.facility = r.facility || existing.facility;
        aggMap.set(key, existing);
    });
    const todayLeadTotals = new Map();
    const todayLeads = getScopedLeadsInRange(todayStart, now);
    todayLeads.forEach((lead) => {
        const key = normalizeJfaName(lead.jfaName);
        if (!key) return;
        const team = lead.jfaTeam || jfaProfiles[key]?.team || '';
        const entry = todayLeadTotals.get(key) || { name: formatJfaName(lead.jfaName), team, count: 0 };
        entry.count += 1;
        if (!entry.team && team) entry.team = team;
        todayLeadTotals.set(key, entry);
    });
    todayLeadTotals.forEach((entry, key) => {
        const existing = aggMap.get(key) || { name: entry.name, team: entry.team, consentForms: 0, productive: false, facility: null };
        existing.consentForms += entry.count;
        if (!existing.team && entry.team) existing.team = entry.team;
        aggMap.set(key, existing);
    });
    aggMap.forEach((val) => aggregated.push(val));
    const sortedByForms = [...aggregated].sort((a, b) => b.consentForms - a.consentForms);
    const topPerformer = sortedByForms[0];

    const topPerformerDiv = document.getElementById('topPerformer');
    if (topPerformerDiv) {
        if (!topPerformer) {
            topPerformerDiv.innerHTML = '<p class="no-data">No submissions yet today</p>';
        } else {
            topPerformerDiv.innerHTML = `
                <div class="highlight-band">
                    <h3>${escapeHtml(topPerformer.name)}</h3>
                    <p>${topPerformer.consentForms} Consent Forms</p>
                    <p style="font-size: 1rem; opacity: 0.9;">${escapeHtml(topPerformer.team || '—')}</p>
                </div>
            `;
        }
    }

    // Top Team
    const teamStats = {};
    const teamMembers = new Map();
    scopedRecords.forEach(record => {
        const team = record.team || '—';
        if (!teamStats[team]) {
            teamStats[team] = { total: 0, members: 0 };
            teamMembers.set(team, new Set());
        }
        teamStats[team].total += record.consentForms || 0;
        const key = normalizeJfaName(record.name);
        if (key) teamMembers.get(team).add(key);
    });
    todayLeads.forEach((lead) => {
        const key = normalizeJfaName(lead.jfaName);
        if (!key) return;
        const team = lead.jfaTeam || jfaProfiles[key]?.team || '—';
        if (!teamStats[team]) {
            teamStats[team] = { total: 0, members: 0 };
            teamMembers.set(team, new Set());
        }
        teamStats[team].total += 1;
        teamMembers.get(team).add(key);
    });
    Object.keys(teamStats).forEach((team) => {
        teamStats[team].members = teamMembers.get(team)?.size || 0;
    });

    const sortedTeams = Object.entries(teamStats).sort((a, b) => b[1].total - a[1].total);
    const teamStatsDiv = document.getElementById('teamStats');
    teamStatsDiv.innerHTML = '';

    sortedTeams.forEach(([team, stats], index) => {
        const teamCard = document.createElement('div');
        teamCard.className = 'team-card';
        const average = stats.members ? (stats.total / stats.members).toFixed(1) : '0.0';
        teamCard.innerHTML = `
            <h4>${index === 0 ? '🥇 ' : index === 1 ? '🥈 ' : index === 2 ? '🥉 ' : ''}${escapeHtml(team)}</h4>
            <p><strong>${stats.total}</strong> Total Consent Forms</p>
            <p><strong>${stats.members}</strong> Active Members</p>
            <p><strong>${average}</strong> Average per Member</p>
        `;
        teamStatsDiv.appendChild(teamCard);
    });

    // Most Productive Facility
    const scopedFacilityIds = new Set(scopedRecords.map((r) => r.facility?.id).filter(Boolean));
    const sortedFacilities = [...facilities]
        .filter(f => (scopedFacilityIds.size ? scopedFacilityIds.has(f.id) : true))
        .filter(f => f.visits.length > 0)
        .sort((a, b) => b.consentForms - a.consentForms);

    const facilityStatsDiv = document.getElementById('facilityStats');
    facilityStatsDiv.innerHTML = '';

    if (sortedFacilities.length > 0) {
        sortedFacilities.slice(0, 5).forEach((facility, index) => {
            const facilityCard = document.createElement('div');
            facilityCard.className = 'facility-card';
            const productiveVisits = facility.visits.filter(v => v.productive).length;
            const productivityRate = facility.visits.length ? Math.round((productiveVisits / facility.visits.length) * 100) : 0;
            const cap = capacityFor(facility);
            const availability = cap - facility.allocations;
            const status = availability <= 0 ? 'Full' : availability <= 1 ? 'Near Full' : 'Available';
            const statusClass = availability <= 0 ? 'chip-danger' : availability <= 1 ? 'chip-warn' : 'chip-ok';
            facilityCard.innerHTML = `
                <h4>${index === 0 ? '🥇 ' : index === 1 ? '🥈 ' : index === 2 ? '🥉 ' : ''}${escapeHtml(facility.name)}</h4>
                <p><strong>${facility.consentForms}</strong> Consent Forms</p>
                <p><strong>${facility.visits.length}</strong> Visits | <strong>${escapeHtml(facility.area)}</strong></p>
                <p><strong>${productivityRate}%</strong> Productivity Rate</p>
                <span class="status-chip ${statusClass}">${status}</span>
            `;
            facilityStatsDiv.appendChild(facilityCard);
        });
    } else {
        facilityStatsDiv.innerHTML = '<p class="no-data">No facility data available yet</p>';
    }

    // Individual Rankings Table
    const rankingsDiv = document.getElementById('individualRankings');
    const rankingRecords = jfaSearchTerm
        ? aggregated.filter((r) => normalizeJfaName(r.name).includes(jfaSearchTerm))
        : aggregated;
    const sortedRankings = [...rankingRecords].sort((a, b) => b.consentForms - a.consentForms);
    if (sortedRankings.length > 0) {
        let tableHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Name</th>
                        <th>Team</th>
                        <th>Consent Forms</th>
                        <th>Facility</th>
                        <th>Monthly Progress</th>
                        <th>Badge</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;

        sortedRankings.forEach((record, index) => {
            const rankClass = index < 3 ? `rank-${index + 1}` : '';
            const rankBadge = `<span class="rank-badge ${rankClass}">#${index + 1}</span>`;
            const productiveIcon = record.productive ? '✓' : '✗';
            const targetMet = (record.consentForms || 0) >= 2;
            const targetBadge = `<span class="target-badge ${targetMet ? 'met' : 'missed'}">${targetMet ? 'Target Met' : 'Below Target'}</span>`;
            const key = normalizeJfaName(record.name);
            const monthTotal = monthTotals.get(key)?.forms || 0;
            const progressPct = Math.min(100, Math.round((monthTotal / CONFIG.MONTHLY_TARGET) * 100));
            let badge = 'Starter';
            if (monthTotal >= 40) badge = 'Gold';
            else if (monthTotal >= 20) badge = 'Silver';
            else if (monthTotal >= 10) badge = 'Bronze';
            const facilityName = record.facility?.name || '—';
            
            tableHTML += `
                <tr>
                    <td>${rankBadge}</td>
                    <td><strong>${escapeHtml(record.name)}</strong></td>
                    <td>${escapeHtml(record.team || '—')}</td>
                    <td><strong>${record.consentForms}</strong></td>
                    <td>${escapeHtml(facilityName)}</td>
                    <td>${monthTotal} (${progressPct}%)</td>
                    <td>${escapeHtml(badge)}</td>
                    <td>${productiveIcon} ${record.productive ? 'Productive' : 'Not Productive'} ${targetBadge}</td>
                </tr>
            `;
        });

        tableHTML += '</tbody></table>';
        rankingsDiv.innerHTML = tableHTML;
    } else {
        rankingsDiv.innerHTML = '<p class="no-data">No rankings available yet</p>';
    }

    updateCoverageByArea();
    updateAlertPanel();
    renderTeamHeatmap();
    renderFacilityForecast();
    renderAuditLog();
    renderAttendancePanel();
    renderTeamTrendChart();
    const updatedEl = document.getElementById('statsLastUpdated');
    if (updatedEl) {
        updatedEl.textContent = new Date().toLocaleString('en-ZA');
    }
    updateLastSaved();
}

function updateDashboardVisibility() {
    const hideTeamSections = adminRole === 'PERSONAL';
    const teamStatsSection = document.getElementById('teamStats')?.closest('.stats-column');
    const heatmapSection = document.getElementById('teamHeatmap')?.closest('.stats-column');
    const trendSection = document.getElementById('teamTrendChart')?.closest('.stats-column');
    if (teamStatsSection) teamStatsSection.style.display = hideTeamSections ? 'none' : '';
    if (heatmapSection) heatmapSection.style.display = hideTeamSections ? 'none' : '';
    if (trendSection) trendSection.style.display = hideTeamSections ? 'none' : '';
}

function renderTeamTrendChart() {
    const container = document.getElementById('teamTrendChart');
    if (!container) return;

    const days = 7;
    const today = new Date();
    const dates = [];
    for (let i = days - 1; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(today.getDate() - i);
        dates.push(d);
    }
    const dateKeys = dates.map((d) => dateKeyLocal(d));
    const archives = getArchives();
    const archiveMap = new Map(archives.map((a) => [a.date, a.records || []]));

    const personalIdentity = adminRole === 'PERSONAL' ? getLeadIdentity() : null;
    const isPersonal = Boolean(personalIdentity?.name);
    const isTeam = adminRole === 'TEAM' && adminTeam;
    const teamSeries = new Map();

    if (isPersonal) {
        teamSeries.set(formatJfaName(personalIdentity.name), new Array(days).fill(0));
    } else if (isTeam) {
        teamSeries.set(adminTeam, new Array(days).fill(0));
    } else {
        const teams = new Set(['Team Thando', 'Team Thato', 'Team Rhulani']);
        archives.forEach((archive) => {
            (archive.records || []).forEach((record) => {
                if (record.team) teams.add(record.team);
            });
        });
        jfaRecords.forEach((record) => {
            if (record.team) teams.add(record.team);
        });
        teams.forEach((team) => teamSeries.set(team, new Array(days).fill(0)));
    }

    dateKeys.forEach((key, index) => {
        const records = key === todayKey() ? jfaRecords : (archiveMap.get(key) || []);
        const scopedRecords = records.filter(recordMatchesScope);
        scopedRecords.forEach((record) => {
            const bucket = isPersonal
                ? formatJfaName(personalIdentity.name)
                : isTeam
                    ? adminTeam
                    : record.team || 'Unassigned';
            if (!teamSeries.has(bucket)) {
                teamSeries.set(bucket, new Array(days).fill(0));
            }
            const series = teamSeries.get(bucket);
            series[index] += record.consentForms || 0;
        });
    });

    const allValues = [];
    teamSeries.forEach((series) => series.forEach((value) => allValues.push(value)));
    const maxVal = Math.max(1, ...allValues);

    container.innerHTML = '';
    const hasData = allValues.some((value) => value > 0);
    if (!hasData) {
        container.innerHTML = '<p class="no-data">No trend data yet</p>';
        return;
    }

    teamSeries.forEach((series, team) => {
        const row = document.createElement('div');
        row.className = 'trend-row';

        const label = document.createElement('div');
        label.className = 'trend-label';
        label.textContent = team;
        row.appendChild(label);

        const bars = document.createElement('div');
        bars.className = 'trend-bars';
        series.forEach((value) => {
            const bar = document.createElement('span');
            bar.className = 'trend-bar';
            const height = Math.max(6, Math.round((value / maxVal) * 40));
            bar.style.height = `${height}px`;
            bar.title = `${value} forms`;
            bars.appendChild(bar);
        });
        row.appendChild(bars);
        container.appendChild(row);
    });

    const axis = document.createElement('div');
    axis.className = 'trend-axis';
    dates.forEach((d) => {
        const label = document.createElement('span');
        label.textContent = d.toLocaleDateString('en-ZA', { month: 'short', day: 'numeric' });
        axis.appendChild(label);
    });
    container.appendChild(axis);
}

function getStartOfDay(date) {
    return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function getStartOfWeek(date) {
    const day = date.getDay();
    const diff = (day === 0 ? -6 : 1) - day;
    const start = new Date(date);
    start.setDate(date.getDate() + diff);
    return getStartOfDay(start);
}

function getWeekKey(date = new Date()) {
    const start = getStartOfWeek(date);
    const end = new Date(start);
    end.setDate(start.getDate() + 4);
    end.setHours(17, 30, 0, 0);
    if (date >= end) {
        const nextStart = new Date(start);
        nextStart.setDate(start.getDate() + 7);
        const nextEnd = new Date(nextStart);
        nextEnd.setDate(nextStart.getDate() + 4);
        return dateKeyLocal(nextEnd);
    }
    return dateKeyLocal(end);
}

function getStartOfMonth(date) {
    return new Date(date.getFullYear(), date.getMonth(), 1);
}

function getScopedRecordsByRange(start, end) {
    const archiveRecords = getArchiveRangeRecords(start, end).filter(recordMatchesScope);
    const liveRecords = jfaRecords
        .filter(recordMatchesScope)
        .filter((record) => {
            if (!record?.timestamp) return false;
            const when = new Date(record.timestamp);
            return when >= start && when <= end;
        });
    return [...archiveRecords, ...liveRecords];
}

function getPersonalCarryoverTarget(now, weekRecords, dailyBase = CONFIG.DAILY_TARGET) {
    const todayStart = getStartOfDay(now);
    const weekStart = getStartOfWeek(now);
    const priorEnd = new Date(todayStart);
    priorEnd.setMilliseconds(-1);
    const priorWeekRecords = filterRecordsByRange(weekRecords, weekStart, priorEnd);
    const priorTotal = priorWeekRecords.reduce((sum, record) => sum + (record.consentForms || 0), 0);
    const workdaysElapsed = getWorkingDays(weekStart, todayStart).length || 1;
    const expectedByToday = workdaysElapsed * dailyBase;
    const carryover = Math.max(0, expectedByToday - priorTotal - dailyBase);
    const dueToday = Math.max(dailyBase, expectedByToday - priorTotal);
    return { dueToday, carryover, expectedByToday, priorTotal, workdaysElapsed };
}

function filterRecordsByRange(records, start, end) {
    return records.filter((r) => {
        if (!r.timestamp) return false;
        const d = new Date(r.timestamp);
        return d >= start && d <= end;
    });
}

function topBy(records, keyFn) {
    const map = new Map();
    records.forEach((r) => {
        const key = keyFn(r);
        if (!key) return;
        map.set(key, (map.get(key) || 0) + (r.consentForms || 0));
    });
    let best = { name: '-', value: 0 };
    map.forEach((value, name) => {
        if (value > best.value) best = { name, value };
    });
    return best;
}

function saveInterventionLog() {
    scheduleStorageWrite(STORAGE_KEYS.interventions, JSON.stringify(interventionLog));
}

function getInterventionEntries(name, team = '') {
    const key = normalizeJfaName(name);
    if (!key) return [];
    const entries = Array.isArray(interventionLog[key]) ? [...interventionLog[key]] : [];
    const scoped = entries.filter((entry) => {
        if (adminRole === 'TEAM' && adminTeam) return (entry.team || team || '') === adminTeam;
        if (team && entry.team) return entry.team === team;
        return true;
    });
    return scoped.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
}

function canEditJfaByTeam(name, team = '') {
    if (adminRole === 'ADMIN') return true;
    if (adminRole !== 'TEAM' || !adminTeam) return false;
    const targetTeam = team || jfaProfiles[normalizeJfaName(name)]?.team || '';
    return targetTeam === adminTeam;
}

function logJfaIntervention(name, source = 'team', noteId = 'interventionNoteTeam', followId = 'interventionFollowTeam', statusId = 'interventionStatusTeam') {
    if (adminRole === 'PERSONAL') {
        showToast('Only team leaders/admin can log interventions.', 'error');
        return;
    }
    if (isTeamLeaderName(name)) {
        showToast('Team leaders are excluded from JFA intervention warnings.', 'error');
        return;
    }
    const noteEl = document.getElementById(noteId);
    const followEl = document.getElementById(followId);
    const statusEl = document.getElementById(statusId);
    const normalized = normalizeJfaName(name);
    if (!normalized) return;
    const team = (jfaRecords.find((record) => normalizeJfaName(record.name) === normalized)?.team
        || jfaProfiles[normalized]?.team
        || '');
    if (!canEditJfaByTeam(name, team)) {
        showToast('You cannot edit this JFA.', 'error');
        return;
    }
    const note = (noteEl?.value || '').trim();
    if (note.length < 4) {
        showToast('Add a brief intervention note before saving.', 'error');
        return;
    }
    const allowed = new Set(['Open', 'In Progress', 'Closed']);
    const status = allowed.has(statusEl?.value) ? statusEl.value : 'Open';
    const entry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        timestamp: new Date().toISOString(),
        note,
        followUpDate: (followEl?.value || '').trim(),
        status,
        team,
        byRole: adminRole
    };
    const bucket = Array.isArray(interventionLog[normalized]) ? interventionLog[normalized] : [];
    bucket.unshift(entry);
    interventionLog[normalized] = bucket.slice(0, 50);
    saveInterventionLog();
    logAudit('Intervention logged', `${formatJfaName(name)} (${team || 'No team'}) - ${status}`);
    showToast('Intervention logged.', 'success');
    if (noteEl) noteEl.value = '';
    if (followEl) followEl.value = '';
    if (statusEl) statusEl.value = 'Open';
    renderAdminTeamDetails();
    renderAdminInsights();
    if (adminRole === 'TEAM' && adminTeam) {
        renderTeamDetailPage(adminTeam);
    }
    openAdminJfaDetail(name, source, true);
}

function getJfaLeadStats(name, team = '') {
    const key = normalizeJfaName(name);
    if (!key) return { total: 0, today: 0, week: 0, month: 0 };
    const now = new Date();
    const today = todayKey();
    const weekStart = getStartOfWeek(now);
    const monthStart = getStartOfMonth(now);
    const mine = leadRecords.filter((lead) => {
        if (normalizeJfaName(lead.jfaName) !== key) return false;
        if (team && lead.jfaTeam && lead.jfaTeam !== team) return false;
        return true;
    });
    const todayCount = mine.filter((lead) => dateKeyLocal(new Date(lead.timestamp)) === today).length;
    const weekCount = mine.filter((lead) => {
        const d = new Date(lead.timestamp);
        return d >= weekStart && d <= now;
    }).length;
    const monthCount = mine.filter((lead) => {
        const d = new Date(lead.timestamp);
        return d >= monthStart && d <= now;
    }).length;
    return { total: mine.length, today: todayCount, week: weekCount, month: monthCount };
}

function getRecentWorkdaySeries(records, length = 5) {
    const today = new Date();
    const dates = [];
    let cursor = new Date(today);
    while (dates.length < length) {
        const day = cursor.getDay();
        if (day !== 0 && day !== 6) {
            dates.unshift(new Date(cursor));
        }
        cursor.setDate(cursor.getDate() - 1);
    }
    const series = dates.map((d) => {
        const key = dateKeyLocal(d);
        const total = records
            .filter((record) => recordDateKey(record) === key)
            .reduce((sum, record) => sum + (record.consentForms || 0), 0);
        return { key, total };
    });
    return series;
}

function getLeadCountForRange(start, end, name = '', team = '') {
    const startTime = start ? new Date(start) : null;
    const endTime = end ? new Date(end) : null;
    const key = name ? normalizeJfaName(name) : '';
    return leadRecords.filter((lead) => {
        if (!lead.timestamp) return false;
        const when = new Date(lead.timestamp);
        if (startTime && when < startTime) return false;
        if (endTime && when > endTime) return false;
        if (adminRole === 'TEAM' && adminTeam && lead.jfaTeam !== adminTeam) return false;
        if (adminRole === 'PERSONAL') {
            const identity = getLeadIdentity();
            if (!identity?.name) return false;
            if (normalizeJfaName(lead.jfaName) !== normalizeJfaName(identity.name)) return false;
        }
        if (team && lead.jfaTeam !== team) return false;
        if (key && normalizeJfaName(lead.jfaName) !== key) return false;
        return true;
    }).length;
}

function getLeadCountForRangeScoped(start, end) {
    return getLeadCountForRange(start, end, '', adminRole === 'TEAM' ? adminTeam : '');
}

function getScopedLeadsInRange(start, end) {
    const startTime = start ? new Date(start) : null;
    const endTime = end ? new Date(end) : null;
    const identity = adminRole === 'PERSONAL' ? getLeadIdentity() : null;
    return leadRecords.filter((lead) => {
        if (!lead.timestamp) return false;
        const when = new Date(lead.timestamp);
        if (startTime && when < startTime) return false;
        if (endTime && when > endTime) return false;
        if (adminRole === 'TEAM' && adminTeam && lead.jfaTeam !== adminTeam) return false;
        if (adminRole === 'PERSONAL') {
            if (!identity?.name) return false;
            if (normalizeJfaName(lead.jfaName) !== normalizeJfaName(identity.name)) return false;
        }
        return true;
    });
}

function buildScopedLeadTotalsMap(leads = []) {
    const totals = new Map();
    (Array.isArray(leads) ? leads : []).forEach((lead) => {
        const key = normalizeJfaName(lead?.jfaName || '');
        if (!key) return;
        const team = lead?.jfaTeam || jfaProfiles[key]?.team || '';
        const entry = totals.get(key) || {
            name: formatJfaName(lead?.jfaName || ''),
            team,
            consentForms: 0
        };
        entry.consentForms += 1;
        if (!entry.team && team) entry.team = team;
        totals.set(key, entry);
    });
    return totals;
}

function appendOrphanLeadCounts(recordsSet = [], leadsSet = []) {
    if (!Array.isArray(recordsSet)) return [];
    if (!Array.isArray(leadsSet) || !leadsSet.length) return [...recordsSet];
    const output = [...recordsSet];
    const knownKeys = new Set(
        recordsSet
            .map((record) => normalizeJfaName(record?.name || ''))
            .filter(Boolean)
    );
    const leadTotals = buildScopedLeadTotalsMap(leadsSet);
    leadTotals.forEach((entry, key) => {
        if (knownKeys.has(key)) return;
        output.push(entry);
    });
    return output;
}

function getScopedFormsTotalForRange(start, end, recordsSet = null) {
    const records = Array.isArray(recordsSet) ? recordsSet : getScopedRecordsByRange(start, end);
    const recordTotal = records.reduce((sum, r) => sum + (Number(r?.consentForms) || 0), 0);
    const recordKeys = new Set(records.map((r) => normalizeJfaName(r?.name || '')).filter(Boolean));
    const leads = getScopedLeadsInRange(start, end);
    let orphanLeadTotal = 0;
    leads.forEach((lead) => {
        const key = normalizeJfaName(lead?.jfaName || '');
        if (!key || recordKeys.has(key)) return;
        orphanLeadTotal += 1;
    });
    return recordTotal + orphanLeadTotal;
}

function getScopedConsentFormsTotalForRange(start, end) {
    // Business rule:
    // - DBD input captures physical paper forms only.
    // - Digital leads are auto-added by the system.
    // This total returns full consent forms = record totals + orphan digital leads.
    return getScopedFormsTotalForRange(start, end);
}

function getConsecutiveUnderDays(series, threshold = CONFIG.DAILY_TARGET) {
    let streak = 0;
    for (let i = series.length - 1; i >= 0; i--) {
        if ((series[i]?.total || 0) < threshold) streak += 1;
        else break;
    }
    return streak;
}

function getPerformanceBand(formsToday, formsMonth) {
    if (formsToday >= 4 || formsMonth >= 20) return { code: 'over', label: 'Performing Strong' };
    if (formsToday >= CONFIG.DAILY_TARGET || formsMonth >= 10) return { code: 'on', label: 'Performing' };
    return { code: 'under', label: 'Under Performing' };
}

function buildTeamRoster(teamName) {
    const today = todayKey();
    const now = new Date();
    const monthStart = getStartOfMonth(now);
    const workingDays = getWorkingDays(monthStart, now);

    const monthRecords = [
        ...getArchiveRangeRecords(monthStart, now),
        ...jfaRecords.filter((r) => r.timestamp)
    ].filter((record) => (record?.team || '') === teamName);

    const allTeamRecords = [
        ...getArchiveRangeRecords(new Date(2000, 0, 1), now),
        ...jfaRecords.filter((r) => r.timestamp)
    ].filter((record) => (record?.team || '') === teamName);

    const roster = new Map();
    Object.entries(jfaProfiles).forEach(([key, profile]) => {
        if ((profile?.team || '') !== teamName) return;
        const fullName = formatJfaName(profile.fullName || `${profile.name || ''} ${profile.surname || ''}`.trim() || key);
        roster.set(normalizeJfaName(fullName), {
            name: fullName,
            team: teamName
        });
    });

    allTeamRecords.forEach((record) => {
        const key = normalizeJfaName(record.name);
        if (!key) return;
        if (!roster.has(key)) {
            roster.set(key, {
                name: formatJfaName(record.name),
                team: teamName
            });
        }
    });

    leadRecords.forEach((lead) => {
        if ((lead.jfaTeam || '') !== teamName) return;
        const key = normalizeJfaName(lead.jfaName);
        if (!key || roster.has(key)) return;
        roster.set(key, {
            name: formatJfaName(lead.jfaName),
            team: teamName
        });
    });

    return [...roster.values()].map((entry) => {
        const key = normalizeJfaName(entry.name);
        const isTeamLeader = isTeamLeaderName(entry.name, teamName);
        const monthMine = monthRecords.filter((record) => normalizeJfaName(record.name) === key);
        const allMine = allTeamRecords.filter((record) => normalizeJfaName(record.name) === key);
        const hasTodayRecord = monthMine.some((record) => recordDateKey(record) === today);
        const hasMonthRecord = monthMine.length > 0;
        const hasAllRecord = allMine.length > 0;
        const formsToday = monthMine
            .filter((record) => recordDateKey(record) === today)
            .reduce((sum, record) => sum + (record.consentForms || 0), 0);
        const formsMonth = monthMine.reduce((sum, record) => sum + (record.consentForms || 0), 0);
        const formsAll = allMine.reduce((sum, record) => sum + (record.consentForms || 0), 0);
        const digitalToday = hasTodayRecord ? 0 : getLeadCountForRange(getStartOfDay(now), now, key, teamName);
        const digitalMonth = hasMonthRecord ? 0 : getLeadCountForRange(monthStart, now, key, teamName);
        const digitalAll = hasAllRecord ? 0 : getLeadCountForRange(new Date(2000, 0, 1), now, key, teamName);
        const formsTodayFinal = formsToday + digitalToday;
        const formsMonthFinal = formsMonth + digitalMonth;
        const formsAllFinal = formsAll + digitalAll;
        const presentDays = new Set(monthMine.map((record) => recordDateKey(record)).filter(Boolean));
        const absentDays = Math.max(0, workingDays.length - presentDays.size);
        const presentToday = formsTodayFinal > 0;
        const leadStats = getJfaLeadStats(entry.name, teamName);
        const series = getRecentWorkdaySeries(monthMine, 5);
        const underStreak = getConsecutiveUnderDays(series, CONFIG.DAILY_TARGET);
        const perf = getPerformanceBand(formsTodayFinal, formsMonthFinal);
        const needsAssistance = !isTeamLeader && perf.code === 'under' && underStreak >= 3;
        const interventions = getInterventionEntries(entry.name, teamName);
        const openInterventions = interventions.filter((item) => item.status !== 'Closed').length;
        const lastInterventionAt = interventions[0]?.timestamp || '';
        const riskMessage = needsAssistance
            ? `${entry.name} is headed in the wrong direction and needs assistance before job risk increases.`
            : '';
        return {
            ...entry,
            presentToday,
            formsToday: formsTodayFinal,
            formsMonth: formsMonthFinal,
            formsAll: formsAllFinal,
            leadsToday: leadStats.today,
            leadsMonth: leadStats.month,
            leadsAll: leadStats.total,
            absences: absentDays,
            isTeamLeader,
            underStreak: isTeamLeader ? 0 : underStreak,
            performanceCode: isTeamLeader ? 'on' : perf.code,
            performanceLabel: isTeamLeader ? 'Team Leader' : perf.label,
            needsAssistance,
            riskMessage,
            openInterventions,
            lastInterventionAt
        };
    }).sort((a, b) => {
        if (a.presentToday !== b.presentToday) return a.presentToday ? -1 : 1;
        return b.formsMonth - a.formsMonth;
    });
}

function updateTargetsAndLeaders(records) {
    const now = new Date();
    const todayStart = getStartOfDay(now);
    const weekStart = getStartOfWeek(now);
    const monthStart = getStartOfMonth(now);
    const end = now;
    const daily = getScopedRecordsByRange(todayStart, end);
    const weekly = getScopedRecordsByRange(weekStart, end);
    const monthly = getScopedRecordsByRange(monthStart, end);
    const dailyLeads = getScopedLeadsInRange(todayStart, end);
    const weeklyLeads = getScopedLeadsInRange(weekStart, end);
    const monthlyLeads = getScopedLeadsInRange(monthStart, end);

    const dailyWithLeads = appendOrphanLeadCounts(daily, dailyLeads);
    const weeklyWithLeads = appendOrphanLeadCounts(weekly, weeklyLeads);
    const monthlyWithLeads = appendOrphanLeadCounts(monthly, monthlyLeads);

    const dailyTotal = getScopedConsentFormsTotalForRange(todayStart, end);
    const weeklyTotal = getScopedConsentFormsTotalForRange(weekStart, end);
    const monthlyTotal = getScopedConsentFormsTotalForRange(monthStart, end);
    const weeklyTargetTotal = CONFIG.WEEKLY_TARGET;
    const monthlyTargetTotal = CONFIG.MONTHLY_TARGET;
    let dailyTargetTotal = CONFIG.DAILY_TARGET;
    let dailyHintText = '';
    let dailyCarryoverNote = '';

    if (adminRole === 'PERSONAL' && getLeadIdentity()?.name) {
        const carryover = getPersonalCarryoverTarget(now, weekly, CONFIG.DAILY_TARGET);
        dailyTargetTotal = carryover.dueToday;
        const shortfall = Math.max(0, dailyTargetTotal - dailyTotal);
        if (carryover.carryover > 0) {
            dailyHintText = `${Math.round((dailyTotal / Math.max(1, dailyTargetTotal)) * 100)}% complete • carryover ${carryover.carryover} from earlier this week`;
        }
        if (shortfall > 0) {
            const tomorrowTarget = CONFIG.DAILY_TARGET + shortfall;
            dailyCarryoverNote = `Below target today. Shortfall ${shortfall} carries to tomorrow. Tomorrow target: ${tomorrowTarget}.`;
        }
    }

    const jfaOnlyDailyWithLeads = dailyWithLeads.filter((r) => !isTeamLeaderName(r.name, r.team || ''));
    const jfaOnlyWeeklyWithLeads = weeklyWithLeads.filter((r) => !isTeamLeaderName(r.name, r.team || ''));
    const jfaOnlyMonthlyWithLeads = monthlyWithLeads.filter((r) => !isTeamLeaderName(r.name, r.team || ''));

    const dailyBestJfa = topBy(jfaOnlyDailyWithLeads, (r) => r.name);
    const dailyBestTeam = topBy(dailyWithLeads, (r) => r.team);
    const weeklyBestJfa = topBy(jfaOnlyWeeklyWithLeads, (r) => r.name);
    const weeklyBestTeam = topBy(weeklyWithLeads, (r) => r.team);
    const monthlyBestJfa = topBy(jfaOnlyMonthlyWithLeads, (r) => r.name);
    const monthlyBestTeam = topBy(monthlyWithLeads, (r) => r.team);
    maybeNotifyLeaderboardChange(now, dailyBestJfa, dailyBestTeam, weeklyBestJfa, weeklyBestTeam);

    const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    setText('dailyTargetProgress', `${dailyTotal} / ${dailyTargetTotal}`);
    setText('weeklyTargetProgress', `${weeklyTotal} / ${weeklyTargetTotal}`);
    setText('monthlyTargetProgress', `${monthlyTotal} / ${monthlyTargetTotal}`);

    setText('dailyBestJfa', `${dailyBestJfa.name} (${dailyBestJfa.value})`);
    setText('dailyBestTeam', `${dailyBestTeam.name} (${dailyBestTeam.value})`);
    setText('weeklyBestJfa', `${weeklyBestJfa.name} (${weeklyBestJfa.value})`);
    setText('weeklyBestTeam', `${weeklyBestTeam.name} (${weeklyBestTeam.value})`);
    setText('monthlyBestJfa', `${monthlyBestJfa.name} (${monthlyBestJfa.value})`);
    setText('monthlyBestTeam', `${monthlyBestTeam.name} (${monthlyBestTeam.value})`);
    setText('dailyTargetCarryoverNote', dailyCarryoverNote);

    updateTargetBar('dailyTargetBar', 'dailyTargetHint', dailyTotal, dailyTargetTotal);
    updateTargetBar('weeklyTargetBar', 'weeklyTargetHint', weeklyTotal, weeklyTargetTotal);
    updateTargetBar('monthlyTargetBar', 'monthlyTargetHint', monthlyTotal, monthlyTargetTotal);
    if (dailyHintText) {
        const dailyHint = document.getElementById('dailyTargetHint');
        if (dailyHint) dailyHint.textContent = dailyHintText;
    }

    renderPeriodLeaderboard('dailyLeaderTable', jfaOnlyDailyWithLeads, (r) => r.name, 'JFA');
    renderPeriodLeaderboard('weeklyLeaderTable', jfaOnlyWeeklyWithLeads, (r) => r.name, 'JFA');
    renderPeriodLeaderboard('monthlyLeaderTable', jfaOnlyMonthlyWithLeads, (r) => r.name, 'JFA');

    renderPeriodLeaderboard('dailyTeamLeaderTable', dailyWithLeads, (r) => r.team, 'Team');
    renderPeriodLeaderboard('weeklyTeamLeaderTable', weeklyWithLeads, (r) => r.team, 'Team');
    renderPeriodLeaderboard('monthlyTeamLeaderTable', monthlyWithLeads, (r) => r.team, 'Team');

    const topTeamOfMonth = monthlyBestTeam.name && monthlyBestTeam.name !== '-' ? monthlyBestTeam.name : '—';
    const topTeamBadge = document.getElementById('topTeamOfMonth');
    if (topTeamBadge) {
        topTeamBadge.textContent = `${topTeamOfMonth} (${monthlyBestTeam.value || 0})`;
    }

    const topJfaOfMonth = monthlyBestJfa.name && monthlyBestJfa.name !== '-' ? monthlyBestJfa.name : '—';
    const topJfaBadge = document.getElementById('topJfaOfMonth');
    if (topJfaBadge) {
        topJfaBadge.textContent = `${topJfaOfMonth} (${monthlyBestJfa.value || 0})`;
    }
}

function updateTargetBar(barId, hintId, total, target) {
    const bar = document.getElementById(barId);
    const hint = document.getElementById(hintId);
    if (!bar) return;
    const pct = target > 0 ? Math.min(100, Math.round((total / target) * 100)) : 0;
    bar.style.width = `${pct}%`;
    bar.classList.remove('is-ontrack', 'is-behind', 'is-critical');
    if (pct >= 100) {
        bar.classList.add('is-ontrack');
    } else if (pct >= 60) {
        bar.classList.add('is-behind');
    } else {
        bar.classList.add('is-critical');
    }
    if (hint) {
        hint.textContent = `${pct}% complete`;
    }
}

function renderPeriodLeaderboard(containerId, records, keyFn, label) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const headerLabel = label || 'JFA';
    const scopedRecords = headerLabel === 'JFA'
        ? records.filter((r) => !isTeamLeaderName(r?.name, r?.team || ''))
        : records;
    if (!scopedRecords.length) {
        container.innerHTML = '<p class="no-data">No data yet</p>';
        return;
    }
    const totals = new Map();
    scopedRecords.forEach((r) => {
        const raw = keyFn ? keyFn(r) : r.name;
        if (!raw) return;
        const key = headerLabel === 'JFA' ? normalizeJfaName(raw) : raw;
        const existing = totals.get(key) || { name: headerLabel === 'JFA' ? formatJfaName(raw) : raw, forms: 0 };
        existing.forms += r.consentForms || 0;
        totals.set(key, existing);
    });
    const top = [...totals.values()]
        .sort((a, b) => b.forms - a.forms)
        .slice(0, 5);
    let html = `<table><thead><tr><th>${headerLabel}</th><th>Forms</th></tr></thead><tbody>`;
    top.forEach((row) => {
        html += `<tr><td>${row.name}</td><td><strong>${row.forms}</strong></td></tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderLeaderboardTable(records, keyFn, label, limit = 5) {
    if (!records.length) return '<p class="no-data">No data yet</p>';
    const totals = new Map();
    records.forEach((r) => {
        const key = keyFn ? keyFn(r) : r.name;
        if (!key) return;
        totals.set(key, (totals.get(key) || 0) + (r.consentForms || 0));
    });
    const top = [...totals.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit);
    let html = `<table><thead><tr><th>${escapeHtml(label)}</th><th>Forms</th></tr></thead><tbody>`;
    top.forEach(([name, forms]) => {
        html += `<tr><td>${escapeHtml(name)}</td><td><strong>${forms}</strong></td></tr>`;
    });
    html += '</tbody></table>';
    return html;
}

function getArchiveRangeRecords(start, end) {
    const archives = getArchives();
    const allRecords = archives.flatMap((a) => a.records || []);
    return allRecords.filter((r) => {
        if (!r.timestamp) return false;
        const d = new Date(r.timestamp);
        return d >= start && d <= end;
    });
}

function getArchiveWeekRange(dateKey) {
    const d = new Date(dateKey);
    const start = getStartOfWeek(d);
    const end = new Date(start);
    end.setDate(start.getDate() + 6);
    end.setHours(23, 59, 59, 999);
    return { start, end };
}

function getArchiveMonthRange(dateKey) {
    const d = new Date(dateKey);
    const start = getStartOfMonth(d);
    const end = new Date(start.getFullYear(), start.getMonth() + 1, 0);
    end.setHours(23, 59, 59, 999);
    return { start, end };
}
