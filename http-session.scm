(module http-session
        (session-table session-create session-refresh! session-valid?
         session-delete! session-ref session-set!
         session-bindings session-delete-binding!
         current-ip current-url session-lifetime session-id-generator)

  (import scheme chicken data-structures utils extras regex)

  (use sha1 posix intarweb spiffy uri-common srfi-1 srfi-18 srfi-69)

  (define (make-table) (make-hash-table equal?))
  ;; key=sid value=(expiration from-ip url-pattern bindings)

  (define session-table (make-parameter (make-table)))

  (define session-lifetime (make-parameter 3600)) ; 1h

  (define (expiration)
    (+ (current-milliseconds)
       (inexact->exact (floor (* (session-lifetime) 1000)))))

  (define (session-create url-pattern #!optional bindings)
    (let ((sid (unique-id))
          (expiration (expiration)))
      (hash-table-set! (session-table) sid (list expiration (current-ip) url-pattern bindings))
      (thread-start!
       (make-thread
        (lambda ()
          (let loop ()
            (let* ((expiration (car (hash-table-ref (session-table) sid)))
                   (timeout (- expiration (current-milliseconds))))
              (when (> timeout 0)
                    (thread-sleep! (/ timeout 1000))
                    (loop))))
          (hash-table-delete! (session-table) sid))))
      sid))

  (define (session-refresh! sid)
    (and-let* ((session (hash-table-ref/default (session-table) sid #f))
               (expiration (expiration)))
              (set-car! session expiration)))

  (define (session-valid? sid)
    (and-let* ((sid sid)
               (session (hash-table-ref/default (session-table) sid #f))
               (ip (current-ip))
               (accessed-url (current-url))
               (url-pattern (caddr session)))
              (and (equal? ip (cadr session))
                   (string-match url-pattern accessed-url))))

  (define (session-delete! sid)
    (hash-table-delete! (session-table) sid))

  (define session-id-generator
    (make-parameter
     (lambda ()
       (sha1-digest (conc (current-milliseconds)
                          (current-process-id)
                          (random (+ 1000 (current-milliseconds))))))))

  (define (unique-id)
    (let try-again ((id ((session-id-generator))))
      (if (session-valid? id)
          (try-again ((session-id-generator)))
          id)))

  (define (session-ref sid var #!optional default)
    (if (session-valid? sid)
        (let ((bindings (last (hash-table-ref/default (session-table) sid '()))))
          (or (alist-ref var bindings) default))
        (error "Invalid session ID.")))

  (define (session-set! sid var val)
    (define (binding-set! session var val)
      (set! session (reverse session))
      (set-car! session (if (car session)
                            (let ((b (assq var (car session))))
                              (if b
                                  (begin
                                    (set-cdr! b val)
                                    (car session))
                                  (append (car session) (list (cons var val)))))
                            (list (cons var val))))
      (set! session (reverse session))
      session)
    (if (session-valid? sid)
        (let* ((session (hash-table-ref/default (session-table) sid #f)))
          (hash-table-set! (session-table) sid (binding-set! session var val)))
        (error "Invalid session ID.")))

  (define (session-bindings sid)
    (if (session-valid? sid)
        (last (hash-table-ref/default (session-table) sid '()))
        (error "Invalid session ID.")))

  (define (session-delete-binding! sid var)
    (alist-delete! var (session-bindings sid)))

  (define (current-ip)
    (remote-address))

  (define (current-url)
    (uri->string (request-uri (current-request))))

  )
