import { TestBed } from '@angular/core/testing';
import { ApiService, ATTOME_CONFIG, LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';
import { CsvImportService } from '../csv/csv-import.service';
import { MigrationWizardComponent } from './migration-wizard.component';

describe('MigrationWizardComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [MigrationWizardComponent],
      providers: [
        { provide: ApiService, useValue: {} },
        { provide: CsvImportService, useValue: {} },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: '' } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (k: string) => k } },
      ],
    });
  });

  it('opens on the CSV file step and switches to pasted JSON on request', () => {
    const fixture = TestBed.createComponent(MigrationWizardComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('xrm-csv-import')).not.toBeNull();
    expect(el.querySelector('#migration-project-name')).toBeNull();

    (el.querySelector('[data-testid="wizard-mode-json"]') as HTMLInputElement).click();
    fixture.detectChanges();
    expect(el.querySelector('xrm-csv-import')).toBeNull();
    expect(el.querySelector('#migration-project-name')).not.toBeNull();
  });
});
