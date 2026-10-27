import { RULE_IDS } from './config.js';
import { type CheckResult, type Finding, RULE_DESCRIPTIONS } from './rules.js';

export type Format = 'text' | 'json' | 'github';

export function render(result: CheckResult, format: Format, color = false): string {
  switch (format) {
    case 'json':
      return JSON.stringify(result, null, 2);
    case 'github':
      return [...result.findings.map(annotation), renderText(result, false)].join('\n');
    case 'text':
      return renderText(result, color);
  }
}

function renderText(result: CheckResult, color: boolean): string {
  const c = palette(color);
  const { tables, views, definers } = result.counted;
  const lines = [
    c.dim(
      `Checked ${tables} tables, ${views} client-readable views and ${definers} client-callable SECURITY DEFINER functions.`,
    ),
    '',
  ];

  const byRule = new Map<string, Finding[]>();
  for (const f of result.findings) {
    byRule.set(f.rule, [...(byRule.get(f.rule) ?? []), f]);
  }
  for (const rule of RULE_IDS) {
    const group = byRule.get(rule);
    if (!group) continue;
    const mark = group.some((f) => f.severity === 'error') ? c.red('✗') : c.yellow('!');
    lines.push(`${mark} ${c.bold(rule)}  ${c.dim(RULE_DESCRIPTIONS[rule])}`);
    for (const f of group) {
      lines.push(`    ${c.bold(f.subject)}: ${f.message}`);
      if (f.fix) lines.push(`      ${c.dim('fix:')} ${f.fix}`);
    }
    lines.push('');
  }

  if (result.openIssues.length > 0) {
    lines.push(
      c.dim(
        `Known gaps (openIssue): ${result.openIssues.map((o) => `${o.subject} → ${o.issue}`).join(', ')}`,
      ),
      '',
    );
  }

  const errors = result.findings.filter((f) => f.severity === 'error').length;
  const warnings = result.findings.length - errors;
  if (errors === 0 && warnings === 0) {
    lines.push(c.green('✓ The database matches its declared posture.'));
  } else {
    lines.push(
      `${errors > 0 ? c.red(`${errors} error${errors === 1 ? '' : 's'}`) : c.green('0 errors')}, ` +
        `${warnings} warning${warnings === 1 ? '' : 's'}.`,
    );
    if (errors > 0) {
      lines.push(
        c.dim(
          'Fix the migration, not the config, unless the new posture is deliberate. Then classify it and say why.',
        ),
      );
    }
  }
  return lines.join('\n');
}

/** A GitHub Actions workflow command, so findings show up on the run summary. */
function annotation(f: Finding): string {
  const level = f.severity === 'error' ? 'error' : 'warning';
  const body = f.fix ? `${f.message}\nfix: ${f.fix}` : f.message;
  return `::${level} title=${escapeProperty(`${f.rule}: ${f.subject}`)}::${escapeData(body)}`;
}

function escapeData(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(s: string): string {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function palette(on: boolean) {
  const wrap = (code: number) => (s: string) => (on ? `\x1b[${code}m${s}\x1b[0m` : s);
  return {
    red: wrap(31),
    green: wrap(32),
    yellow: wrap(33),
    bold: wrap(1),
    dim: wrap(2),
  };
}
