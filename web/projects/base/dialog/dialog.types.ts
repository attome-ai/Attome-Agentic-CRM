export interface ConfirmOptions {
  title?: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: 'primary' | 'danger' | 'warning';
  icon?: string;
}

export interface PromptOptions {
  title: string;
  /**
   * NGB-3.2 — the input's accessible name. Falls back to `title` when absent,
   * which is what the host used to have to omit entirely (the prompt input had
   * no label at all).
   */
  label?: string;
  message?: string;
  value?: string;
  placeholder?: string;
  confirmText?: string;
  cancelText?: string;
  selectStem?: boolean;
  validator?: (value: string) => string | null;
}

export interface ErrorDialogOptions {
  title?: string;
  message: string;
  details?: string;
  buttonText?: string;
}

export type DialogState =
  | {
      kind: 'confirm';
      options: ConfirmOptions;
      resolve: (val: boolean) => void;
    }
  | {
      kind: 'prompt';
      options: PromptOptions;
      resolve: (val: string | null) => void;
    }
  | {
      kind: 'error';
      options: ErrorDialogOptions;
      resolve: () => void;
    }
  | null;
