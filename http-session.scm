(module http-session
        (session-table session-create session-refresh! session-valid?
         session-delete! session-ref session-set! session-set-finalizer!
         session-bindings session-delete-binding!
         session-lifetime session-id-generator
         make-session-table match-ip-address? session-destroy! session-del!)

  (import scheme chicken data-structures utils extras regex)

  (use sha1 posix intarweb spiffy uri-common srfi-1 srfi-18 srfi-69)

  (define (make-session-table) (make-hash-table equal?))
  ;; key=sid value=#<session-item expiration from-ip bindings>

  (define session-table (make-parameter (make-session-table)))

  (define match-ip-address? (make-parameter #f))

  (define session-lifetime (make-parameter 3600)) ; 1h

  (define (expiration)
    (+ (current-milliseconds)
       (inexact->exact (floor (* (session-lifetime) 1000)))))

  (define-record session-item expiration ip bindings finalizer)

  (define (get-session-item sid #!optional (error? #t))
    (handle-exceptions
     exn
     (if error?
         (error (conc "Invalid session ID: " sid))
         #f)
     (hash-table-ref (session-table) sid)))
    
  (define (session-create #!optional (bindings '()))
    (let ((sid (unique-id))
          (expiration (expiration)))
      (hash-table-set! (session-table) sid (make-session-item expiration (remote-address) bindings #f))
      (thread-start!
       (make-thread
        (lambda ()
          (let loop ()
            (let* ((sitem (get-session-item sid))
                   (timeout (- (session-item-expiration sitem) (current-milliseconds))))
              (when (> timeout 0)
                    (thread-sleep! (/ timeout 1000))
                    (loop))))
          (hash-table-delete! (session-table) sid))))
      sid))

  (define (session-refresh! sid)
    (session-item-expiration-set! (get-session-item sid) (expiration)))

  (define (session-valid? sid)
    (not (not (and sid
                   (and-let* ((sitem (get-session-item sid #f)))
                     (if (match-ip-address?)
                         (equal? (remote-address) (session-item-ip sitem))
                         #t))))))

  (define (session-destroy! sid)
    (let ((finalizer (session-item-finalizer (get-session-item sid))))
      (when finalizer (finalizer sid)))
    (hash-table-delete! (session-table) sid))
  
  (define session-delete!  ;; DEPRECATED
    session-destroy!)

  (define session-id-generator
    (make-parameter
     (lambda ()
       (sha1-digest (conc (current-milliseconds)
                          (current-process-id)
                          (random (+ 1000 (inexact->exact
                                           (current-milliseconds)))))))))

  (define (unique-id)
    (let try-again ((id ((session-id-generator))))
      (if (session-valid? id)
          (try-again ((session-id-generator)))
          id)))

  (define (session-ref sid var #!optional default)
    (or (alist-ref var (session-item-bindings (get-session-item sid)))
        default))
  
  (define (session-set! sid var val)
    (let* ((sitem (get-session-item sid))
	   (new-bindings (alist-update! var val (session-item-bindings sitem))))
      (session-item-bindings-set! sitem new-bindings)))

  (define (session-set-finalizer! sid proc)
    (session-item-finalizer-set! (get-session-item sid) proc))

  (define (session-bindings sid)
    (session-item-bindings (get-session-item sid)))
  
  (define (session-del! sid var)
    (alist-delete! var (session-bindings sid)))

  (define session-delete-binding! ;; DEPRECATED
    session-del!)
  
  )
