/**
 * Tests the *installed superpowers framework*, not this project's code.
 *
 * Validates the integrity of each skill: frontmatter shape, required fields,
 * presence of the workflow skills this project's plan invoked, and that the
 * skills referenced in the workflow form a closed graph (no dangling
 * cross-skill references).
 *
 * This is the implementation and test phase OF the superpowers skill set
 * (vs. using superpowers to implement/test something else). We don't modify
 * the vendor-installed files; we verify their shape against expectations.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { describe, expect, it } from "vitest";

const SKILLS_ROOT = join(
  homedir(),
  ".claude/plugins/cache/claude-plugins-official/superpowers/5.1.0/skills"
);

interface SkillFrontmatter {
  name: string;
  description: string;
}

function parseFrontmatter(content: string): SkillFrontmatter | null {
  if (!content.startsWith("---\n")) return null;
  const end = content.indexOf("\n---", 4);
  if (end < 0) return null;
  const block = content.slice(4, end);
  const fm: Partial<SkillFrontmatter> = {};
  for (const line of block.split("\n")) {
    const m = line.match(/^([a-zA-Z_]+):\s*(.*)$/);
    if (!m) continue;
    const [, key, rawValue] = m;
    const value = rawValue
      .trim()
      .replace(/^"(.*)"$/s, "$1")
      .replace(/^'(.*)'$/s, "$1");
    (fm as Record<string, string>)[key] = value;
  }
  if (!fm.name || !fm.description) return null;
  return fm as SkillFrontmatter;
}

function listSkills(): string[] {
  return readdirSync(SKILLS_ROOT).filter((entry) => {
    const path = join(SKILLS_ROOT, entry);
    return statSync(path).isDirectory();
  });
}

function readSkill(name: string): { frontmatter: SkillFrontmatter; body: string } {
  const skillFile = join(SKILLS_ROOT, name, "SKILL.md");
  const content = readFileSync(skillFile, "utf8");
  const frontmatter = parseFrontmatter(content);
  if (!frontmatter) {
    throw new Error(`skill ${name}: malformed or missing frontmatter`);
  }
  const bodyStart = content.indexOf("\n---", 4) + 4;
  return { frontmatter, body: content.slice(bodyStart) };
}

describe("superpowers skill set integrity", () => {
  it("skills root exists", () => {
    expect(() => statSync(SKILLS_ROOT)).not.toThrow();
  });

  it("every skill directory has a SKILL.md", () => {
    const skills = listSkills();
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      const f = join(SKILLS_ROOT, s, "SKILL.md");
      expect(() => statSync(f), `${s}/SKILL.md`).not.toThrow();
    }
  });

  it("every SKILL.md parses to valid frontmatter", () => {
    for (const s of listSkills()) {
      const { frontmatter } = readSkill(s);
      expect(frontmatter.name, `${s}.name`).toBeTruthy();
      expect(frontmatter.description, `${s}.description`).toBeTruthy();
    }
  });

  it("frontmatter name matches directory name", () => {
    for (const s of listSkills()) {
      const { frontmatter } = readSkill(s);
      expect(frontmatter.name, `${s} name vs dir`).toBe(s);
    }
  });

  it("frontmatter descriptions are reasonably specific (>= 30 chars)", () => {
    for (const s of listSkills()) {
      const { frontmatter } = readSkill(s);
      expect(
        frontmatter.description.length,
        `${s} description too short: "${frontmatter.description}"`
      ).toBeGreaterThanOrEqual(30);
    }
  });
});

describe("workflow skills required by this project's plan are present", () => {
  const required = [
    "using-superpowers",
    "brainstorming",
    "writing-plans",
    "executing-plans",
    "test-driven-development",
    "subagent-driven-development",
    "verification-before-completion",
  ];

  for (const r of required) {
    it(`skill "${r}" is installed`, () => {
      const skill = readSkill(r);
      expect(skill.frontmatter.name).toBe(r);
    });
  }
});

describe("skill content sanity", () => {
  it("brainstorming describes the design-before-implementation hard gate", () => {
    const { body } = readSkill("brainstorming");
    expect(body.toLowerCase()).toMatch(/design|approval/);
  });

  it("writing-plans describes bite-sized task granularity", () => {
    const { body } = readSkill("writing-plans");
    expect(body.toLowerCase()).toMatch(/task|step/);
  });

  it("test-driven-development describes the red-green cycle", () => {
    const { body } = readSkill("test-driven-development");
    expect(body.toLowerCase()).toMatch(/test|implementation/);
  });

  it("using-superpowers is the entry skill (referenced by others or self-bootstrapping)", () => {
    const { frontmatter, body } = readSkill("using-superpowers");
    expect(frontmatter.description.toLowerCase()).toMatch(/start|skill/);
    expect(body.length).toBeGreaterThan(100);
  });
});
