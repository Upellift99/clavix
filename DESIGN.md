---
name: Clavix
description: A Vaultwarden desktop client in the category standard, signed by a machined seal and one verdigris accent.
colors:
  verdigris: "#0f8b8d"
  deep-teal: "#0b5c5e"
  mint: "#bfe9e4"
  mint-wash: "#e3f3f1"
  mint-selected: "#d4ecea"
  teal-link: "#0c6f71"
  verdigris-lifted: "#3fb3b1"
  verdigris-pale: "#7fd1cd"
  cool-ground: "#f4f6f6"
  paper: "#ffffff"
  cool-pane: "#eaeded"
  cool-header: "#f7f9f9"
  cool-inset: "#eef1f1"
  cool-code: "#e6eaea"
  row-hover: "#eef3f3"
  ink: "#16191a"
  ink-secondary: "#2e3538"
  ink-label: "#4b5356"
  ink-muted: "#6c767a"
  ink-faint: "#7f898d"
  ink-disabled: "#a4adb0"
  hairline: "#d8dcdc"
  hairline-input: "#c9cfcf"
  hairline-accent: "#cfe3e2"
  hairline-soft: "#e6eaea"
  danger-red: "#b42318"
  error-wash: "#fdecec"
  warning-amber-text: "#7a4b00"
  warning-wash: "#fff4dc"
  success-green: "#15803d"
  star-gold: "#e0a400"
  status-fresh: "#22c55e"
  status-busy: "#f59e0b"
  status-offline: "#ef4444"
  status-unknown: "#9ca3af"
  dark-ground: "#171a1b"
  dark-surface: "#1f2425"
  dark-pane: "#262c2d"
  dark-header: "#1c2122"
  dark-code: "#30373a"
  dark-ink: "#eceff0"
  dark-ink-muted: "#a9b3b6"
  dark-hairline: "#343b3d"
  dark-hairline-input: "#3f4749"
  dark-accent-wash: "#1f3c3d"
  dark-accent-active: "#255052"
  camera-well: "#000000"
typography:
  display:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 600
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.3rem"
    fontWeight: 600
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.05rem"
    fontWeight: 600
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.85rem"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "\"cv11\", \"ss01\", \"ss03\""
  data:
    fontFamily: "Atkinson Hyperlegible, Inter, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.92rem"
    fontWeight: 400
  password:
    fontFamily: "Atkinson Hyperlegible, ui-monospace, monospace"
    fontSize: "0.92rem"
    fontWeight: 400
    letterSpacing: "0.08em"
  label:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.72rem"
    fontWeight: 600
    letterSpacing: "0.06em"
  small:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 400
  base:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.45
  heading:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.95rem"
    fontWeight: 600
    letterSpacing: "-0.01em"
  dialog-title:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.15rem"
    fontWeight: 600
  auth-title:
    fontFamily: "Atkinson Hyperlegible, Inter, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "1.45rem"
    fontWeight: 700
rounded:
  hairline: "3px"
  icon: "4px"
  control: "6px"
  panel: "8px"
  dialog: "10px"
  pill: "999px"
spacing:
  hair: "0.15rem"
  xs: "0.25rem"
  sm: "0.4rem"
  md: "0.6rem"
  lg: "0.85rem"
  xl: "1.25rem"
components:
  button-primary:
    backgroundColor: "{colors.verdigris}"
    textColor: "{colors.paper}"
    rounded: "{rounded.control}"
    padding: "0.45rem 0.7rem"
    height: "2.25rem"
  button-primary-hover:
    backgroundColor: "{colors.deep-teal}"
    textColor: "{colors.paper}"
  button-secondary:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink-secondary}"
    rounded: "{rounded.control}"
    padding: "0.45rem 0.7rem"
    height: "2.25rem"
  button-secondary-hover:
    backgroundColor: "{colors.row-hover}"
    textColor: "{colors.ink-secondary}"
  button-danger:
    backgroundColor: "{colors.danger-red}"
    textColor: "{colors.paper}"
    rounded: "{rounded.control}"
  button-icon:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.icon}"
    size: "2rem"
  button-icon-hover:
    backgroundColor: "{colors.mint-wash}"
    textColor: "{colors.deep-teal}"
  input:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    rounded: "{rounded.control}"
    padding: "0.45rem 0.7rem"
    height: "2.25rem"
  panel:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "0.6rem 0.85rem"
  tree-pane:
    backgroundColor: "{colors.cool-pane}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "0.4rem 0.35rem"
  tree-row-selected:
    backgroundColor: "{colors.mint-selected}"
    textColor: "{colors.deep-teal}"
    rounded: "{rounded.control}"
    padding: "0.2rem 0.45rem"
  list-row-selected:
    backgroundColor: "{colors.verdigris}"
    textColor: "{colors.paper}"
    padding: "0.2rem 0.5rem"
    height: "2.25rem"
  badge:
    backgroundColor: "{colors.mint-wash}"
    textColor: "{colors.deep-teal}"
    rounded: "{rounded.hairline}"
    padding: "0.03rem 0.35rem"
  dialog:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.dialog}"
    padding: "1.25rem 1.5rem"
  toast:
    backgroundColor: "{colors.deep-teal}"
    textColor: "{colors.paper}"
    rounded: "{rounded.panel}"
    padding: "0.6rem 1rem"
---

# Design System: Clavix

## Overview

**Creative North Star: "The Precise Seal"**

Clavix takes the category standard of desktop password managers, with Bitwarden Desktop and KeePassXC as the bar, and plays it straight. A user coming from either product reads the shell without learning anything: a toolbar across the top, a folder tree on the left, a dense item list in the centre, a detail panel below. Only two things are not conventional, and they are what a user remembers afterwards: the mark, a machined seal with a knurled rim and a C pressed into the disc, and the verdigris accent on every action and selection. Everything else is neutral, even, and quiet on purpose.

The register is dense and precise rather than spacious. Surfaces are white and cool-tinted grey, separated by one-pixel hairlines instead of shadows. Every control is the same height, every panel the same radius, and the accent appears only where the user acts or where something is selected. State colours (green, amber, red, grey) appear only where a state is being named, never as decoration. The dark theme is a first-class sibling, not an override: the whole palette is one block of tokens written twice and tested for parity.

The system refuses the category's lazy rendition: the Tauri template blue, white cards floating on one-pixel shadows, controls of three different heights, a selection colour that is also the hover colour, and Bitwarden's primary blue.

**Key Characteristics:**
- One accent family (verdigris, deep teal, mint) and nothing else saturated in the chrome.
- Cool-tinted neutrals: white surfaces on a grey-green ground, hairline borders, no card shadows.
- Two faces with a strict division of labour: Inter for the interface, Atkinson Hyperlegible for every secret and identifier.
- Uniform 36 px controls and rows, 6 px control radius, 8 px panel radius, 10 px dialog radius.
- Selection is filled verdigris with white text in the list and a mint pill with deep-teal text in the tree; hover is always a lighter, distinct tint.
- Light and dark are token-identical sets, enforced by a test.

## Colors

A cool neutral field with one verdigris accent family and a small, literal set of state colours.

### Primary
- **Verdigris** (#0f8b8d): the only saturated colour in the chrome. Fills primary buttons, the selected list row, the focus ring, the mark's disc, the splitter line on hover, the multi-select tick bar and the active preferences tab underline. Identical in both themes.
- **Deep Teal** (#0b5c5e): the pressed state of verdigris. Primary button hover, link hover, accent-coloured text on light surfaces (badge text, selected tree node, column header hover), the clipboard toast for passwords, the logo tile and the C's impression. Identical in both themes.
- **Mint** (#bfe9e4): the lightest member of the family. Icon-button active background, hover border, splitter hover fill, the mark's hairline ring. Dark theme uses the accent washes instead.
- **Mint Wash** (#e3f3f1): the resting accent tint. Icon-button hover, tree row hover, the badge background, the multi-selection row tint, the bulk-action bar. In dark it becomes Dark Accent Wash (#1f3c3d).
- **Mint Selected** (#d4ecea): the tree's selected pill and the multi-selection hover. In dark it is Dark Accent Wash.
- **Teal Link** (#0c6f71): underlined text links on light surfaces; Verdigris Pale (#7fd1cd) in dark.
- **Verdigris Lifted** (#3fb3b1) and **Verdigris Pale** (#7fd1cd): the dark theme's lift of the accent. Lifted is the focus ring, the splitter line and the tick bar in dark; Pale is accent text, badge text, links and the selected tree node in dark. Lifted also outlines a folder being renamed in both themes.

### Neutral
- **Paper** (#ffffff): the surface of panels, the list, the detail, inputs, dialogs and the toolbar. Dark Surface (#1f2425) in dark.
- **Cool Ground** (#f4f6f6): the window background behind the panels. Dark Ground (#171a1b) in dark.
- **Cool Pane** (#eaeded): the tree pane, one step darker than paper so the navigation reads as a different material. Dark Pane (#262c2d) in dark.
- **Cool Header** (#f7f9f9): the list's column header strip and the zebra stripe. Dark Header (#1c2122) in dark.
- **Cool Inset** (#eef1f1) and **Cool Code** (#e6eaea): the generator output, SSH key blocks, preformatted text and inline code. Dark Ground and Dark Code (#30373a) in dark.
- **Row Hover** (#eef3f3): list row and menu item hover, and secondary button hover. Deliberately two steps from both paper and the zebra so hover is never confused with either.
- **Ink** (#16191a): primary text, the wordmark, headings. Dark Ink (#eceff0) in dark.
- **Ink Secondary** (#2e3538): form labels, secondary button text, notes.
- **Ink Label** (#4b5356): definition-list terms and muted data values (usernames and URLs in the list). Lifted to #c1c9cc in dark.
- **Ink Muted** (#6c767a): tracked-caps section labels, hints, status text, counts, placeholders' neighbours. Dark Ink Muted (#a9b3b6) in dark.
- **Ink Faint** (#7f898d) and **Ink Disabled** (#a4adb0): placeholders, detail footers and location paths; disabled text and the empty-state icon.
- **Hairline** (#d8dcdc): every panel border, divider, splitter and tree guide line. Dark Hairline (#343b3d) in dark.
- **Hairline Input** (#c9cfcf): the slightly firmer border of inputs, secondary buttons and menus. Dark Hairline Input (#3f4749) in dark.
- **Hairline Accent** (#cfe3e2) and **Hairline Soft** (#e6eaea): the toolbar's and selection bar's cool-tinted border; the softest row separators inside lists.

### State
- **Danger Red** (#b42318): the delete button fill and destructive menu items; in dark the text lifts to #f28b82 while the fill stays. Also colours symbol characters in a revealed password.
- **Error Wash** (#fdecec) with #7a1d1d text and #e5a0a0 border: error boxes and inline error messages.
- **Warning Amber** (#7a4b00 on #fff4dc, border #f0d08a): the alpha warning callout, SSH passphrase hints, skipped-key badges. In dark the text is #f0c070 on #3a2f1a.
- **Success Green** (#15803d; #6ecf9a in dark): strong password verdicts, audit all-clear, SSH agent running.
- **Star Gold** (#e0a400): the favourite star, same in both themes.
- **Status dot** colours Fresh (#22c55e), Busy (#f59e0b), Offline (#ef4444), Unknown (#9ca3af): the toolbar's sync indicator only, each with a 20% halo of its own colour. Identical in both themes.
- **Drop target** (#fde68a fill, #78350f text, #f59e0b outline): the one moment a saturated non-accent colour appears in the tree, because during a drag the only question is where the item will land.

### Named Rules
**The One Family Rule.** Verdigris, deep teal and mint are the only saturated colours in the chrome. Red, amber, green and the status greys appear only where a state is being named: an error, a warning, a verdict, a sync status, a drop target.

**The Hover Is Not Selection Rule.** Hover and selection never share a colour. The list hovers at Row Hover and selects in filled verdigris; the tree hovers at Mint Wash and selects at Mint Selected with deep-teal text and semibold weight.

**The One Block Rule.** Every colour resolves to a custom property in `src/styles/tokens.css`. The dark theme is the same list of tokens with different values, written twice (system dark and forced dark) and kept byte-identical by `src/styles/tokens.test.ts`. No component carries its own dark override.

## Typography

**Display Font:** Inter (with the system sans stack)
**Body Font:** Inter (with the system sans stack)
**Data Font:** Atkinson Hyperlegible (with Inter, then the system sans stack)

**Character:** Inter carries the interface with its single-storey alternates on (cv11, ss01, ss03) so it reads as a neutral, finished product face. Atkinson Hyperlegible carries every piece of user data, because a username, a URL and a password must be read correctly the first time; its distinct 0, O, 1, l and I are the point. The pairing is quiet; the two faces are close enough in colour that the switch registers as "this is data", not as a change of voice.

### Hierarchy
- **Display** (600, 1.6rem, tracking -0.02em): the "Clavix" brand name beside the mark on the auth screens only.
- **Headline** (600, 1.3rem, tracking -0.01em): the page h1 on the auth screens; 1.15rem in the wide vault layout.
- **Title** (600, 1.05rem, tracking -0.01em): dialog titles and the detail panel's item name. The list heading "Items (n)" is one step down at 0.95rem with the count at 0.85rem regular and muted.
- **Body** (400, 0.85rem, line-height 1.45): the working size of the interface: tree labels, form labels, list paths, popovers, hints at 0.78 to 0.82rem. Item names in the list sit at 0.92rem.
- **Data** (400, 0.92rem, Atkinson Hyperlegible): every value in the detail panel, every text input and textarea, notes at 0.88rem, usernames and URLs in the list at 0.88rem in Ink Label, inline code and preformatted blocks.
- **Password** (400, Atkinson Hyperlegible, tracking 0.08em): revealed passwords in the detail panel; 0.04em inside editable password and TOTP inputs. Digits are coloured deep teal (Verdigris Pale in dark) and symbols Danger Red, both semibold, following the KeePassXC convention.
- **Label** (600, 0.72rem, tracking 0.06em, uppercase): column headers in the list, section titles in the detail panel and the editor's custom-fields legend, in Ink Muted or Ink Faint. The tree's section headers use the same size, tracking 0.05em.

### Named Rules
**The Secret Reads Right Rule.** Anything the user did not type into the interface as a command is data: usernames, passwords, URLs, codes, notes, fingerprints, SSH keys. Data is always set in Atkinson Hyperlegible. Buttons, menus, labels and headings are always Inter. Selects stay in Inter even inside a form.

**The Auth Screens Rule.** Login, unlock, two-factor and onboarding switch the whole screen to Atkinson Hyperlegible and lift form sizing by about ten percent (inputs and buttons at 1.05rem, labels at 0.95rem, headings at 1.45rem) so the master password is comfortable to read under fatigue or in dim light.

**The Tabular Count Rule.** Counts, dates, sizes and strength figures use tabular numerals so columns of numbers line up.

## Layout

The vault is a three-region shell inside a full-height flex column with 0.5rem between regions and 0.6rem by 0.75rem of padding against the window. The toolbar is a bordered 44 px strip across the top on a paper surface: mark and wordmark on the left behind a hairline, groups of 32 px icon buttons separated by hairline dividers, the status dot and label pushed right. Below it the vault layout is a grid of a 260 px tree pane (user-resizable), a 6 px splitter and the list; the detail panel sits under the list behind a horizontal 6 px splitter and scrolls on its own.

Row rhythm is uniform at 36 px: list rows, tree rows and every control share the same 2.25rem minimum height. The list is virtualised, zebra-striped by absolute index, and lays out a 1.25rem icon column, then name, identifier and URL columns at 2fr, 1.4fr and 2fr. The detail panel is a label grid with a fixed 130 px label column and 0.85rem gap; the notes block and strength bar indent themselves to the value column with the same two numbers.

Spacing runs on quarter-rem steps: 0.15rem between grouped icon buttons, 0.25rem inside menus and around tree sections, 0.4rem as the default gap in rows and forms, 0.6rem between form fields and columns, 0.85rem for panel padding and the detail label gap, 1.25rem for dialog padding and auth-screen rhythm.

Responsive behaviour is desktop-only reflow: below 900 px the URL column disappears, below 760 px the tree collapses onto the list and the wordmark and status label hide behind the dot, below 720 px the detail grid stacks labels over values, below 680 px the list shows name only. Dialogs are `min(560px, 94vw)` for the editor, `min(640px, 96vw)` for import and export, `min(760px, 100vw - 3rem)` for preferences, all capped near the viewport height and scrolling inside their frame.

## Elevation & Depth

The system is flat. Panels, boxes, the toolbar, the tree pane and the list all sit on the ground with a one-pixel hairline border and no shadow; depth between regions comes from the two-step tonal difference between Cool Ground, Cool Pane and Paper (and their dark equivalents). The two card-level shadow tokens exist and are set to none on purpose so nothing can quietly reintroduce a floating card. Shadows are reserved for what truly floats above the page: popovers, context menus, dialogs and the clipboard toast, each behind a tinted backdrop where modal.

### Shadow Vocabulary
- **Popover** (`box-shadow: 0 4px 14px rgba(22, 25, 26, 0.1)`; `rgba(0,0,0,0.45)` in dark): the column chooser and the clipboard toast.
- **Menu** (`box-shadow: 0 6px 24px rgba(22, 25, 26, 0.16)`; `rgba(0,0,0,0.55)` in dark): right-click context menus over the tree and the list.
- **Dialog** (`box-shadow: 0 12px 36px rgba(22, 25, 26, 0.22)`; `rgba(0,0,0,0.65)` in dark): the editor, preferences, import and export panels, over a `rgba(22,25,26,0.4)` backdrop (`rgba(0,0,0,0.55)` in dark).

### Named Rules
**The Borders Do That Job Rule.** Nothing at rest casts a shadow. A surface earns a shadow only by floating over the page: a menu, a popover, a dialog, a toast.

## Shapes

Corners step with the size of the thing: 3 px on the smallest chips (badges, inline code), 4 px on icon buttons, menu items and keyboard hints, 6 px on controls, inputs, menus, popovers and the tree's selected pill, 8 px on panels, boxes, forms and the toast, 10 px on dialogs. List rows are square-cornered because they fill their container edge to edge; the list container itself carries the 8 px radius and its header strip rounds only its top corners. Borders are one pixel everywhere; the only thicker strokes are the 2 px focus ring, the 2 px preferences-tab underline, the 3 px inset tick bar on a multi-selected row and the 2 px outline on a drop target. The status dot is a full circle with a 2 px halo. The mark is pure geometry: concentric circles and one arc, no text, no gradients.

## Components

### Buttons
Standard, same height, quiet until hovered.
- **Shape:** gently rounded controls (6 px), 2.25rem minimum height, 0.45rem by 0.7rem padding, Inter 500.
- **Primary:** Verdigris fill, white text, verdigris border. Hover darkens to Deep Teal. One per surface: "Éditer" in the detail header, "Enregistrer" in the editor footer, the submit on auth forms.
- **Secondary:** Paper fill, Ink Secondary text, Hairline Input border. Hover fills Row Hover. Used for "Dupliquer", "Annuler", tree quick filters and every non-committing action.
- **Danger:** Danger Red fill and border, white text; "Supprimer" in the detail header and the bulk-action bar. Destructive menu items are red text on transparent, hovering to Error Wash.
- **Icon buttons:** transparent with a transparent 1 px border, 2rem square in the toolbar and 1.7rem in the detail panel, 4 px radius, icon in the current text colour. Hover fills Mint Wash with a Mint border and deep-teal icon; active fills Mint. Transitions are 100 ms.
- **Small:** 1.85rem high, 0.82rem text, for inline actions such as "Ajouter un champ".
- **Focus:** a 2 px Verdigris outline offset 1 px (Verdigris Lifted in dark). Rows and tabs use the same ring inset 2 px.
- **Disabled:** 60% opacity, progress cursor.

### Inputs / Fields
- **Style:** Paper fill, Hairline Input border, 6 px radius, 2.25rem minimum height, Atkinson Hyperlegible for text inputs and textareas, Inter for selects. Placeholders in Ink Faint.
- **Focus:** border turns Verdigris and a 2 px halo of verdigris at 22% alpha appears (30% in dark). No outline.
- **Password fields:** a 1.6rem reveal button sits inside the right edge, Ink Muted, hovering to deep teal on Row Hover. Revealed values track at 0.04em.
- **Strength meter:** four 4 px segments with 3 px gaps, resting on Hairline, filling weak in Danger Red, fair in Warning Amber, good and strong in Success Green, with a 0.8rem verdict in the same colour and the entropy in Ink Muted tabular figures.
- **Labels:** stacked above the field, 0.85rem Ink Secondary, 0.25rem gap. Checkbox rows flip to inline.

### Panels and Boxes
- **Corner Style:** 8 px.
- **Background:** Paper; the tree pane alone is Cool Pane.
- **Shadow Strategy:** none, per Elevation.
- **Border:** 1 px Hairline.
- **Internal Padding:** 0.6rem by 0.85rem for boxes, 0.85rem by 1rem for the detail panel, 1rem for standalone forms.

### Toolbar
A paper strip with a cool accent hairline, 6 px radius, 0.3rem by 0.5rem padding. The 20 px mark and the 0.95rem semibold wordmark sit left behind a hairline; icon-button groups follow with hairline dividers; the status sits right at 0.8rem Ink Muted with a 0.5rem dot that pulses while syncing. The toolbar can switch to a centred three-column grid where the buttons sit on the window's centre line.

### Tree
A Cool Pane panel with 0.4rem by 0.35rem padding. Sections carry 0.72rem tracked uppercase headers in Ink Muted. Rows are transparent 6 px-radius buttons at 0.85rem, 0.2rem by 0.45rem padding, with a 1.1rem chevron toggle and a right-aligned tabular count in Ink Muted. Children indent 0.75rem behind a hairline guide. Hover fills Mint Wash; the selected node fills Mint Selected with deep-teal semibold text. A droppable node shows a dashed Verdigris Pale outline, and the live drop target flips to amber regardless of hover or selection. Renaming swaps the label for an input outlined in Verdigris Lifted.

### List
A paper container with 8 px radius and a Cool Header strip carrying 0.72rem tracked uppercase sortable column headers; the active sort reads deep teal at 700. Rows are 36 px, 0.2rem by 0.5rem padding, 1.3 line-height, a 16 px type icon then name at 0.92rem and identifier and URL at 0.88rem Atkinson in Ink Label. Even rows zebra at Cool Header; hover is Row Hover (one step darker on zebra rows); the open row fills Verdigris with white text and its data columns at 85% opacity. Multi-selected rows tint Mint Wash with a 3 px inset Verdigris bar and keep the bar when also open. A bulk-action bar appears above the list in Mint Wash with a cool accent hairline. The empty state is a centred Ink Disabled icon, a 0.95rem Ink Label title and 0.85rem body.

### Detail Panel
A paper panel that mounts with a 140 ms fade and 4 px slide. The header puts the type badge (Mint Wash, deep-teal text, 3 px radius, 0.72rem 500) before the 1.05rem semibold title, the folder path in 0.8rem Ink Faint under it, and the actions right: primary, secondaries, danger, then a close icon. Fields are a 130 px label grid, labels 0.82rem Ink Muted 500, values 0.92rem Atkinson with 1.7rem icon buttons for reveal and copy. Section titles are 0.72rem tracked caps in Ink Faint.

### Dialogs
Native-feeling modal panels: Paper, 10 px radius, 1.25rem by 1.5rem padding, dialog shadow, tinted backdrop. The title row is 1.05rem semibold with a close icon button right. The editor pins its action row to the bottom behind a hairline so "Annuler" and "Enregistrer" stay visible while the form scrolls. Preferences use a tab strip of transparent buttons with a 2 px underline that turns Verdigris and deep-teal text when selected, hovering to Ink on Row Hover. Error and warning notices inside dialogs are 6 px-radius washes in their state colours.

### Menus and Popovers
Surface Raised with a Hairline Input border, 6 px radius, menu shadow, 0.25rem padding. Items are 4 px-radius transparent buttons, 0.4rem by 0.6rem, hovering to Row Hover; destructive items are Danger text hovering to Error Wash behind a hairline separator. Keyboard hints sit right in a 0.72rem Atkinson chip on the keyboard-hint tint.

### Clipboard Toast
A solid pill fixed bottom centre, 8 px radius, 0.6rem by 1rem, white text, popover shadow, with a white secondary button that takes the pill's colour as its text. The pill's colour names what was copied through four dedicated tokens: Deep Teal for a password, Verdigris for a username, a dark slate teal (#30474a) for a TOTP code, Dark Code grey for anything else. The four tokens are identical in both themes because each tint already reads on a light or a dark page.

### The Mark
"Le sceau précis", inline SVG in a 512 viewBox: a knurled rim (a dashed ring in Verdigris), a filled Verdigris disc, a hairline Mint ring, and a C in white over a Deep Teal offset impression. In the app it is 20 px in the toolbar and larger beside the brand name on the auth screens, driven by the accent tokens so it follows the theme. The shipped logo adds a Deep Teal tile with 112 px corners behind the same geometry; every icon size and the favicon derive from `assets/clavix-logo.svg`.

### Icons
A monochrome inline set in a 24 viewBox, 2 px stroke, round caps and joins, Lucide-style geometry, default 16 px, taking the current text colour. Decorative by default; labelled only when no surrounding text carries the meaning. The refresh icon spins at one turn per second while a sync is in flight.

## Do's and Don'ts

### Do:
- **Do** resolve every colour to a custom property in `src/styles/tokens.css`, and add any new token to the light block and both dark blocks so `tokens.test.ts` stays green.
- **Do** set every username, password, URL, code, note, fingerprint and key in Atkinson Hyperlegible (`--font-data`), and keep buttons, labels, headings and selects in Inter.
- **Do** keep controls and rows at the shared 2.25rem (36 px) height, 6 px radius on controls, 8 px on panels, 10 px on dialogs.
- **Do** separate regions with 1 px hairlines and the Cool Ground / Cool Pane / Paper tonal steps, and reserve shadows for menus, popovers, dialogs and the toast.
- **Do** use the verdigris family for action, selection and focus only, and keep hover a distinct lighter tint from selection.
- **Do** use red, amber, green and the status greys only where a state is being named, and say the state in words as well.
- **Do** give every state its own visible answer: selected, multi-selected, hovered, focused, droppable and drop-over are all distinct in the tree and list.
- **Do** pass every user-visible string through Paraglide messages; no literal copy in components.

### Don't:
- **Don't** reintroduce a per-component dark override (`prefers-color-scheme` or `.force-dark` outside `tokens.css`). The theme is one block of tokens.
- **Don't** write a hex or rgba colour in a component or stylesheet outside `tokens.css`.
- **Don't** bring back Bitwarden's blue (#175ddc), the Tauri template blue, or any second saturated accent in the chrome.
- **Don't** add side-tab accents, coloured left bars on navigation, or coloured section headers; the tree selects with a mint pill, nothing else.
- **Don't** invent controls: use standard buttons, inputs, selects, native dialogs and details/summary popovers, styled by the base rules.
- **Don't** put a shadow under a card, panel, box or the toolbar; the card shadow tokens are none on purpose.
- **Don't** let hover and selection share a colour, or let selection depend on colour alone (the tree also goes semibold; the list also inverts text).
- **Don't** show a secret or identifier in Inter or a system monospace; the confusable-free data face is a product commitment.
