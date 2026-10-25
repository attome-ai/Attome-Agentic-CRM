{{- define "attome.name" -}}{{ .Release.Name }}-attome{{- end -}}

{{- define "attome.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}

{{- define "attome.labels" -}}
app.kubernetes.io/name: attome
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
One pod spec: the attome binary with one subcommand, the configuration
Secret mounted at /etc/attome and named by CONFIG_FILE. Call with
(dict "root" . "component" "<name>" "command" "<subcommand>" "extra" <dict>),
where extra holds container fields (ports, probes, resources).
*/}}
{{- define "attome.pod" -}}
containers:
  - name: {{ .component }}
    image: {{ include "attome.image" .root }}
    imagePullPolicy: {{ .root.Values.image.pullPolicy }}
    args: [{{ .command | quote }}]
    env:
      - name: CONFIG_FILE
        value: /etc/attome/{{ .root.Values.config.key }}
    {{- if .root.Values.envFromSecret }}
    envFrom:
      - secretRef:
          name: {{ .root.Values.envFromSecret }}
    {{- end }}
    volumeMounts:
      - name: config
        mountPath: /etc/attome
        readOnly: true
    {{- with .extra }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
volumes:
  - name: config
    secret:
      secretName: {{ .root.Values.config.secretName }}
{{- end -}}
