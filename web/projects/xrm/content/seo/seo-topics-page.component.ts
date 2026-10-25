import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import { SeoTopic, SeoService } from './seo.service';
import { RobotsEditorComponent } from './robots-editor.component';

/**
 * E13-T12: the site's search topics (a pillar page and its cluster), with
 * the robots.txt editor below. Topics are added by name and language and
 * removed after a second click; their pages are set on the topic.
 */
@Component({
  selector: 'attome-seo-topics-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, RobotsEditorComponent],
  template: `
    <section class="st" data-testid="seo-topics">
      <h2>{{ 'e13.topicsTitle' | translate }}</h2>
      @if (error(); as message) { <p class="st-error" role="alert">{{ message }}</p> }
      <form class="st-add" (ngSubmit)="add()">
        <label>
          <span>{{ 'e13.topicName' | translate }}</span>
          <input type="text" maxlength="200" [(ngModel)]="name" name="stName" required />
        </label>
        <label>
          <span>{{ 'e13.topicLanguage' | translate }}</span>
          <select [(ngModel)]="language" name="stLanguage">
            <option value="ar">{{ 'e13.languageAr' | translate }}</option>
            <option value="en">{{ 'e13.languageEn' | translate }}</option>
          </select>
        </label>
        <button type="submit" class="btn-primary" [disabled]="!name.trim() || busy()">
          {{ 'e13.addTopic' | translate }}
        </button>
      </form>
      @if (topics().length === 0) {
        <p class="st-muted">{{ 'e13.noTopics' | translate }}</p>
      } @else {
        <ul class="st-list">
          @for (t of topics(); track t.id) {
            <li [attr.data-topic]="t.id">
              <span class="st-name">{{ t.name }}</span>
              <span class="st-muted">{{ t.language }}</span>
              @if (t.pillar_page_ref) { <span class="st-muted">{{ 'e13.hasPillar' | translate }}</span> }
              <button type="button" class="btn-ghost" (click)="remove(t)">
                {{ (deleting() === t.id ? 'e13.confirmDelete' : 'e13.deleteTopic') | translate }}
              </button>
            </li>
          }
        </ul>
      }
      <attome-robots-editor />
    </section>
  `,
  styles: [`
    .st { display: grid; gap: 0.8rem; }
    .st-add { display: flex; gap: 0.6rem; align-items: end; flex-wrap: wrap; }
    .st-add label { display: grid; gap: 0.25rem; }
    .st-list { list-style: none; padding-inline-start: 0; display: grid; gap: 0.4rem; }
    .st-list li { display: flex; gap: 0.6rem; align-items: center; }
    .st-name { font-weight: 600; }
    .st-muted { color: var(--text-muted, #6b7280); }
    .st-error { color: var(--danger, #b91c1c); }
  `],
})
export class SeoTopicsPageComponent implements OnInit {
  private readonly seo = inject(SeoService);

  name = '';
  language = 'ar';
  readonly topics = signal<SeoTopic[]>([]);
  readonly busy = signal(false);
  readonly deleting = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.seo.topics().subscribe({
      next: page => this.topics.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  add(): void {
    const name = this.name.trim();
    if (!name) return;
    this.busy.set(true);
    this.seo.createTopic({ name, language: this.language, pillar_page_ref: null }).subscribe({
      next: topic => {
        this.topics.update(list => [...list, topic]);
        this.name = '';
        this.busy.set(false);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }

  /** The first click arms, the second removes. */
  remove(topic: SeoTopic): void {
    if (this.deleting() !== topic.id) {
      this.deleting.set(topic.id);
      return;
    }
    this.seo.deleteTopic(topic.id).subscribe({
      next: () => {
        this.topics.update(list => list.filter(t => t.id !== topic.id));
        this.deleting.set(null);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
