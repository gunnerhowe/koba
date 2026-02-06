export interface HelpContent {
  title: string;
  description: string;
  analogy?: string;
  analogyIcon?: string;
  steps: string[];
  tips?: string[];
}

export const helpContent: Record<string, HelpContent> = {
  dashboard: {
    title: 'Dashboard',
    description:
      'This is your home screen. It shows you a summary of everything your AI assistant has been doing. You can see how many actions it took, how many were allowed, how many were blocked, and how many are waiting for your permission.',
    analogy:
      "A receptionist's front desk. When you walk in, they give you a quick summary: \"You had 12 visitors today. 10 were let in. 2 were turned away.\"",
    analogyIcon: '\u{1F3E2}',
    steps: [
      'Look at the colored number boxes at the top. Green means actions that were allowed. Red means actions that were blocked. Yellow means actions waiting for you to decide.',
      'Scroll down to see the most recent things your AI did, with the newest at the top.',
      'If you see something that concerns you, click on it to see more details.',
      'The connection status in the top-right corner tells you if the system is working. Green dot means everything is fine.',
    ],
    tips: [
      'This page updates automatically. You do not need to refresh it.',
      'If the numbers are all zero, your AI has not done anything yet. That is perfectly normal if you just set things up.',
    ],
  },

  tools: {
    title: 'What Can Your AI Do?',
    description:
      'This is the most important page. It shows every action your AI assistant is capable of \u2014 like sending emails, reading files, or making payments. For each action, YOU choose whether to Allow it, Require your Approval first, or Block it completely.',
    analogy:
      'A list of house keys. You decide which doors your housekeeper can open on their own, which ones they need to ask you about first, and which ones are permanently locked.',
    analogyIcon: '\u{1F511}',
    steps: [
      'Start with Quick Setup: choose "Log Only" (let AI do everything while you watch), "Recommended" (risky actions need your OK), or "Maximum Protection" (everything needs your OK).',
      'Then customize individual tools below if you want. Browse the colored category tiles (Email, Files, Calendar, etc.) and click any tile to see the tools inside.',
      'For each tool, you will see three buttons: Allow (green), Approval (yellow), and Block (red). Click the one you want.',
      'Green (Allow) means the AI can do this anytime without asking you. Yellow (Approval) means the AI must ask you first every time. Red (Block) means the AI can NEVER do this.',
      'Your choices are saved immediately to the server. You can change them anytime.',
    ],
    tips: [
      'If you are not sure, start with "Recommended." It lets the AI read things freely but asks your permission before doing anything risky.',
      'You can use the "Set all" buttons at the top of each category to quickly set every tool in that group to the same setting.',
    ],
  },

  approvals: {
    title: 'Pending Approvals',
    description:
      'When your AI wants to do something you marked as "Requires Approval," it shows up here and waits for your permission. Nothing happens until you say yes or no. The AI cannot proceed without you.',
    analogy:
      'A child asking "Can I?" before doing something. They stand at the door and wait until you say "yes, go ahead" or "no, not right now."',
    analogyIcon: '\u{1F6AA}',
    steps: [
      'Look at the list of pending requests. Each one shows what the AI wants to do and when it asked.',
      'Click the green "Approve" button to let the AI proceed, or the red "Reject" button to say no.',
      'If you reject a request, you can optionally type a reason. This gets saved for your records.',
      'Click on a request to see exactly what the AI is trying to do before you decide.',
    ],
    tips: [
      'This page checks for new requests automatically every 5 seconds.',
      'If the list is empty and shows "All Clear," that means nothing is waiting for you. You can come back later.',
      'Approving a request lets the AI do that ONE specific action. It does not change your tool settings permanently.',
    ],
  },

  monitoring: {
    title: 'Activity Alerts',
    description:
      'This page watches your AI for unusual behavior. If the AI starts doing things that seem odd or different from its normal pattern, warnings appear here. Think of it as a security camera that alerts you when something looks wrong.',
    analogy:
      'A home security system with motion sensors. Most of the time, nothing happens. But if something unusual moves in the middle of the night, an alarm goes off and you get alerted.',
    analogyIcon: '\u{1F514}',
    steps: [
      'Check the colored stat boxes at the top. If "High Risk Sessions" shows zero, everything is normal.',
      'Use the three tabs below to switch between: "Alert Events" (individual warnings), "Safety Monitors" (the sensors watching the AI), and "Session States" (each conversation the AI is having).',
      'If you see a warning with a high score (above 80%), it means the system is fairly confident something unusual happened. Review it carefully.',
      'If you are an admin, you can reset a session to clear its warnings.',
    ],
    tips: [
      'A warning does NOT automatically mean something bad happened. It means something unusual was detected. Always review before taking action.',
      'This page is most useful after your AI has been running for a while and has established normal patterns.',
    ],
  },

  safeguarding: {
    title: 'AI Safeguarding System',
    description:
      'This is your emergency control room. It lets you see the safety systems protecting you from your AI doing something dangerous. It includes a Kill Switch that can instantly stop all AI operations, controls over AI self-modifications, resource limits, and behavior monitors.',
    analogy:
      'The circuit breaker panel in your house. Normally you never touch it. But if something goes wrong with the electricity, you can flip a switch and immediately cut the power to stay safe.',
    analogyIcon: '\u{1F50C}',
    steps: [
      'Check the green or red banner at the top. Green "SAFEGUARDING ACTIVE" means everything is running normally and your safety systems are on.',
      'Use the tabs to explore: "Overview" shows a summary, "Modifications" shows if the AI is asking to change itself, "Kill Switch" is the emergency stop, and "Cognitive" shows behavior pattern alerts.',
      'If you ever need to stop all AI operations immediately, go to the Kill Switch tab. This requires multiple key holders to activate, like needing two keys to open a safety deposit box.',
      'The "Modifications" tab shows when the AI requests to change its own code or behavior. These always require your approval and have a mandatory waiting period.',
    ],
    tips: [
      'You need admin access to see this page. If you cannot see it, ask your system administrator.',
      'The Kill Switch is a last resort. In normal operation, you will never need to use it.',
      'Resource limits prevent the AI from using too much computing power. These are set automatically and protect you without any action needed.',
    ],
  },

  receipts: {
    title: 'Receipts',
    description:
      'Every single action your AI takes creates a signed receipt \u2014 like a digital record with a tamper-proof signature. This page lets you browse through all of those receipts. Each receipt proves exactly what the AI did, when it did it, and what the decision was.',
    analogy:
      'A filing cabinet full of stamped, signed receipts \u2014 like the ones you get when you buy something at a store. Each one proves a transaction happened and cannot be forged or changed.',
    analogyIcon: '\u{1F5C4}\uFE0F',
    steps: [
      'Scroll through the list to see all receipts, newest first.',
      'Use the search bar at the top to find a specific receipt by typing the tool name, the AI agent name, or the receipt ID.',
      'Click on any receipt to see its full details, including the cryptographic signature that proves it is genuine.',
      'Use the page buttons at the bottom to see older receipts.',
    ],
    tips: [
      'Receipts cannot be edited or deleted by anyone \u2014 not even administrators. This is by design, to ensure the record is trustworthy.',
      'The colored badges tell you the decision: green means Allowed, red means Blocked, yellow means it needed Approval.',
    ],
  },

  receiptDetail: {
    title: 'Receipt Details',
    description:
      'You are looking at one specific receipt. This is the complete, tamper-proof record of a single action your AI took. It includes what happened, who authorized it, and a cryptographic signature that proves this record is genuine and has not been altered.',
    analogy:
      'A notarized document. Every detail is recorded, and the notary stamp at the bottom proves it is authentic. If anyone changed even one word, the stamp would no longer match.',
    analogyIcon: '\u{1F4DC}',
    steps: [
      'Read the summary at the top to see what tool was used and what the decision was.',
      'Look at the green verification badges. "Signature Valid" means the receipt has not been tampered with. "Merkle Proof Verified" means it is included in the official log.',
      'Scroll down to see the full technical details, including the raw signature data.',
      'Use the "Copy" buttons to copy any value if you need to share it with someone.',
    ],
    tips: [
      'Both verification checks (Signature and Merkle Proof) should show green. If either shows red, something may be wrong.',
      'You can share a receipt ID with anyone and they can independently verify it on the Verify page.',
    ],
  },

  merkleTree: {
    title: 'Proof Log',
    description:
      'This page shows you proof that your records have not been tampered with. All of your receipts are organized into a special structure that makes it impossible to secretly change, delete, or rearrange any past records.',
    analogy:
      'Imagine a chain where every link is locked to the one before it. If someone tried to change a link in the middle, the whole chain after it would break and everyone would notice instantly. That is what this page proves about your records.',
    analogyIcon: '\u{26D3}\uFE0F',
    steps: [
      'Look at the "Tree Size" number to see how many receipts are protected.',
      'The "Integrity Fingerprint" is a unique code for ALL your records combined. If even one receipt were changed, this code would be completely different.',
      'The signature at the bottom proves that Koba has officially committed to this exact set of records.',
      'Scroll down to see the tree visualization showing how records are organized.',
    ],
    tips: [
      'You do not need to understand the technical details. The key takeaway is: if this page shows a valid signature, your records are intact.',
      'This page updates automatically as new receipts come in.',
    ],
  },

  verify: {
    title: 'Verify a Receipt',
    description:
      'This page lets you check whether a specific receipt is genuine. You paste in a receipt ID, and the system checks two things: (1) is the digital signature valid? and (2) does this receipt actually exist in the tamper-proof log? If both checks pass, you can trust the receipt is real.',
    analogy:
      'Checking if a banknote is real. You hold it up to the light to see the watermark, and you check the serial number against a database. If both checks pass, the money is genuine.',
    analogyIcon: '\u{1F50D}',
    steps: [
      'Paste or type a Receipt ID into the text box. You can get this ID from the Receipts page.',
      'Click the "Verify" button.',
      'Wait a moment while the system checks the receipt.',
      'A green checkmark means the receipt is genuine and untampered. A red X means something is wrong \u2014 the receipt may have been altered or does not exist.',
    ],
    tips: [
      'Both checks must pass: the digital signature AND the Merkle proof. If either fails, the receipt should not be trusted.',
      'You can share a receipt ID with anyone and they can verify it independently.',
    ],
  },

  integrations: {
    title: 'Integrations',
    description:
      'This page shows all the AI tools and platforms that can connect to Koba. You can set up new connections here so that Koba can watch over and govern your AI agents, no matter which platform they run on.',
    analogy:
      'The outlets and plugs in your house. Different devices need different types of plugs, but they all connect to the same electrical system. This page shows which AI "devices" can plug into Koba.',
    analogyIcon: '\u{1F50C}',
    steps: [
      'Browse the list of available integrations on the left.',
      'Click on any integration card to see how to set it up.',
      'Follow the setup instructions shown. Each integration is different, but they all connect back to Koba.',
      'Once connected, your AI agent will automatically be governed by the rules you set on the Tools page.',
    ],
    tips: [
      'You may need technical help to set up some integrations. That is normal \u2014 it is usually a one-time setup.',
      'After setup, everything works automatically. You do not need to come back here unless you want to add more connections.',
    ],
  },

  users: {
    title: 'Users',
    description:
      'This page shows everyone who has access to this Koba dashboard. You can see their names, roles, and when they last logged in. If you have permission, you can add new users, change their roles, or deactivate accounts.',
    analogy:
      'A list of everyone who has a key to the office. You can see who they are, what rooms they can access, and when they last came in.',
    analogyIcon: '\u{1F465}',
    steps: [
      'Look at the list to see who has access and what role they have.',
      'Roles control what each person can do: "Super Admin" can do everything. "Admin" can manage most things. "Operator" can approve actions. "Viewer" can only look but not change anything.',
      'To add a new user, click the "Create User" button (if visible).',
      'To change someone\'s role, click the edit button next to their name.',
    ],
    tips: [
      'Only users with the right permissions can see this page.',
      'Be careful when giving someone the "Admin" or "Super Admin" role. They will be able to change settings and approve AI actions.',
    ],
  },

  settings: {
    title: 'Settings',
    description:
      'This page lets you configure how Koba works. You can adjust security policies, change your password, and set system-wide preferences. Most settings have safe defaults, so you do not need to change anything unless you want to.',
    analogy:
      'The thermostat and control panel for your house. Everything works with the factory settings, but you can adjust things to your preference.',
    analogyIcon: '\u{1F39B}\uFE0F',
    steps: [
      'Use the tabs at the top to switch between "General" settings, "Security" settings, and your "Profile."',
      'To change your password, go to the "Profile" tab and fill in your old password, then your new password twice.',
      'Security settings show which safety features are turned on.',
      'Click "Save" after making any changes.',
    ],
    tips: [
      'If you are not sure what a setting does, leave it at the default value.',
      'Only admins can change the General settings. All users can change their own password in the Profile tab.',
    ],
  },

  tenants: {
    title: 'Tenants',
    description:
      'If your organization manages multiple separate groups or companies, each one is called a "tenant." This page lets system administrators create and manage these separate groups. Each tenant has its own users, settings, and AI policies, completely separate from the others.',
    analogy:
      'An apartment building manager\'s office. Each apartment (tenant) is separate \u2014 the people in Apartment A cannot see or change anything in Apartment B. You manage them all from one place.',
    analogyIcon: '\u{1F3E2}',
    steps: [
      'Look at the list of existing tenants and their status.',
      'To add a new tenant (group/company), click the "Create Tenant" button.',
      'Each tenant operates independently with its own set of rules and users.',
      'You can suspend a tenant to temporarily disable their access without deleting them.',
    ],
    tips: [
      'Most organizations only need one tenant. You only need this page if you manage multiple separate groups.',
      'This page is only visible to Super Admins.',
    ],
  },

  apiKeys: {
    title: 'API Keys',
    description:
      'API keys are like passwords that allow computer programs to connect to Koba. This page lets system administrators create, view, and revoke these keys. Each key gives a specific level of access.',
    analogy:
      'Spare keys to your house that you give to trusted service people. You can make new ones, see who has one, and deactivate any key if you do not want that person to have access anymore.',
    analogyIcon: '\u{1F5DD}\uFE0F',
    steps: [
      'Look at the list of existing API keys. Each shows when it was created and what permissions it has.',
      'To create a new key, click the "Create API Key" button and choose what level of access it should have.',
      'To deactivate a key, click the revoke button next to it. This immediately stops anyone using that key from connecting.',
      'Copy a new key immediately after creating it \u2014 it will only be shown once for security.',
    ],
    tips: [
      'Never share API keys by email or chat. Treat them like passwords.',
      'Only system administrators can access this page.',
      'If you think a key has been compromised, revoke it immediately and create a new one.',
    ],
  },
};
