;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of How to hack a system
;;; Returns a nested plan structure (through unification)
;;; consisting of :sequential/:parallel groupings
;;; of (:goal ... :plan ...) structures
;;; and (:action ... structures
;;;
;;; Note: Several of the operators could take advantage of the guards field
;;; rather than the pre-requisite.  Guards get tested before bindings are done
;;; but they might need to do some of their own binding
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(in-package :aplan)



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; the top level queries
;;;
;;; Any desirable property
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This is set up to attack a desirable property of any computer resource?
;;; But the component it goes after is part of the OS.
;;; So this is one method, not the only.  It's the generic method that says
;;; go after some piece of the OS that can affect the desirable property of the victim.
;;; For example, if the victim is a web-server and the goal is to affect its data-privacy
;;; then one way you might go after this is to get hold of some piece of the os and use
;;; that to violate the web-server's data-privacy.
;;; But, there are other methods: for example penetrate some component of the web-server
;;; and use that to violate data-privacy.

(defattack-method affect-property-by-controlling-impacting-component
    :to-achieve [affect ?desirable-property ?victim]
    ;; find some component of the OS of a machine that the victim runs on
    :bindings ((?computer ?victim.machines)
               (?os-instance ?computer.os)
	       ;; The simpler path notation won't work
	       ;; here because ?computer.os.? is ambiguous
	       ;; and would give both parts and slot-values
               [part-of ?os-instance ?component]
	       [current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?victim computer-resource)
             (?os-instance operating-system)
	     (?component process))
    :prerequisites ([impacts ?component-property ?component ?desirable-property ?victim])
    :plan (:sequential
           ;; this breaks down into two steps:
           ;; 1) Get control of some component of the victim
           ;; 2) Use that control to affect the property of the victim
           ;; Notice that the first step is oblivous to its purpose
           ;; This certainly makes things simpler but might lead to getting control in a way
           ;; that doesn't actually work
           (:goal [takes-control-of ?attacker ?component-property ?component])
           (:goal [use-control-of-to-affect-resource ?attacker ?component ?desirable-property ?victim]))
    )

(defattack-method affect-property-by-affecting-input
    :to-achieve [affect ?desirable-property ?victim]
    :prerequisites ([impacts ?resource-property ?resource ?desirable-property ?victim])
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?resource computer-resource))
    :plan (:goal [affect ?resource-property ?resource])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; ToDo: More lateral motion stuff
;;; When you do the achieve connection, you need to know what protocols
;;; might be useful.  So we condition this by using protocol-is-relevant-for
;;; need to do more of that.


;;; Note: This could be done more indirectly by saying that 
;;; performance is inversely proportional to workload size
;;; and then having a rule that says that to decrease something that
;;; is inversely proportional to something else increaese the something else

(defattack-method increase-workload-to-decrease-performance
    :to-achieve [affect performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ((?os ?process.host-os)
	       (?computer ?os.machine)
	       (?workload ?os.workload)
	       [protocol-is-relevant-for workload-size ?protocol]
	       [attacker-and-machine ?attacker  ?attacker-machine])
    :typing ((?process process)
	     (?os operating-system)
	     (?workload os-workload))
    :plan (:sequential
	   (:goal [get-foothold ?computer ?protocol])
	   (:goal [increase-size ?workload]))
    )

(defattack-method send-lots-of-emails
    :to-achieve [affect performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ((?os-instance ?process.host-os)
	       (?computer ?os.machine)
	       [current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?process email-server-process)
	     (?foothold-machine computer))
    :plan (:sequential
	   (:goal [get-foothold ?computer email])
	   (:repeated-action [submit-email ?attacker large-email ?process ?foothold-machine ?foothold-role]))
    :post-conditions ([current-foothold ?foothold-context ?foothold-machine ?foothold-role])
    )

;;; now what we want to say is:
;;; Either 
;;; 1) find a process in the current workload that is capable of launching new jobs
;;; get control of that process and cause it launch jobs.  For example, a server that takes 
;;; requests through some protocol and launches jobs in response (e.g. web server ftp server)
;;; repeatedly connect to it and cause it to launch a job
;;; 2) Increase the size of the job launch queue

(defattack-method increase-workload-by-increasing-job-launch-queue
    :to-achieve [increase-size ?workload]
    :bindings ((?os ?workload.os)
	       (?queue ?os.job-launch-queue)
	       (?user-job-launch-queue ?queue.user-job-launch-request-queue)
	       [current-foothold ?foothold-machine ?foothold-role]
	       )
    :typing ((?workload os-workload)
	     (?os operating-system)
	     (?queue os-job-launch-request-queue)
	     (?user-job-launch-queue job-launch-request-queue))
    :plan (:goal [increase-size ?user-job-launch-queue]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Privacy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method read-file-property-directly
    :to-achieve [affect data-privacy ?file]
    :prerequisites ([desirable-property-of ?file data-privacy])
    :typing ((?file data-resource))
    :plan (:goal [achieve-knowledge-of-contents ?file])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Integrity
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Fix: Need to do an get-foothold to get foothold
(defattack-method write-file-property-directly
    :to-achieve [affect data-integrity ?file]
    :typing ((?file file))
    :prerequisites ([desirable-property-of ?file data-integrity])
    :plan (:goal [modify contents ?file])
    )

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defattack-method mung-process-output
    :to-achieve [affect data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set]
	       [attacker-and-machine ?attacker ?attacker-machine])    
    :typing ((?process process))
    :plan (:sequential
           (:goal [takes-control-of ?attacker data-integrity ?process])
           (:goal [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]))
    )

(defattack-method mung-database
    :to-achieve [affect data-integrity ?database]
    :bindings ((?database-machine ?database.machines)
	       (?database-os ?database-machine.os)
	       [current-foothold ?current-foothold-machine ?current-foothold-role])
    :typing ((?database database)
	     (?current-foothold-role attacker)
	     (?database database)
	     (?database-os operating-system))
    :prerequisites ([has-permission ?current-foothold-role write ?database])
    ;; Shouldn't there be a pre-requisite that the attacker has the requirement
    :plan (:sequential
	   ;; Note that get-foothold treats the next-to-last two arguments as things that it binds.
	   ;; Also note that it might bind these to the same thine as the current foothold
	   ;; Also note that it returns in a state where you have remote-execution on the new-foothold-machine
	   ;; And you've opened a connecion to the victim machine
	   (:goal [get-foothold ?database-machine database-protocol])
	   (:goal [make-connection ?database-machine database-protocol])
	   (:goal [modify data-integrity ?database])
	   )
    )

(defattack-method actually-make-connection
    :to-achieve [make-connection ?victim-machine ?connection-type]
    :bindings ([current-foothold ?current-foothold-machine ?current-foothold-role])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?connection-type])

    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Direct Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-directly
    ;; Takes control of a component to ultimately affect some property of the target
    :to-achieve [takes-control-of ?attacker ?component-property ?component]
    :plan (:goal [takes-direct-control-of ?attacker ?component-property ?component]))

;;; one way to take direct control of a process is to
;;; first find some way to modify the loadable file so as to affect the property of the target
;;; and then cause the load of the loadable file of the program that's supposed to run in the process

;;; Fix modify
(defattack-method control-process-through-loadable-files
    :to-achieve [takes-direct-control-of ?attacker ?victim-property ?victim]
    :bindings ((?program ?victim.program)
               (?file ?program.load-files))
    :typing ((?victim process)
             (?program program)
             (?file dynamically-loadable-code-file))
    :plan (:sequential 
           (:goal [modify contents ?file ?input-context])
	   ;; Note: this is a hack right now.  Really it should be a goal which would involve
	   ;; a series of actions to cause the file to get loaded (logging in?, robooting?)
           (:action [load-file ?attacker ?file ?victim]))
    )

;;; Fixed:
;;; This mentions the host-os but it doesn't actually seem to carry through
;;; to the plan.  Just rationality check, I guess.
(defattack-method buffer-overflow-can-control-server-processes
    :to-achieve [takes-direct-control-of ?attacker ?process-property ?process]
    ;; :bindings ([ltms:value-of (?process host-os) ?os-instance])
    :typing ((?process process)
             ;; (?os-instance operating-system)
             )
    :prerequisites ((is-vulnerable-to ?process 'buffer-overflow-attack))
    :plan (:action [take-control-with-buffer-overflow ?attacker ?process])
    )

(defrule check-vulnerabiity (:backward)
  then [is-vulnerable-to ?process ?attack]
  if (is-vulnerable-to ?process ?attack))

;;; How to do the supertyping
(defun is-vulnerable-to (process attack)
  (labels ((do-one-type (type)
             (let ((type-name (ji::object-type-name type)))
               (ask `[protected-from ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values nil))))
               (ask `[vulnerable-to ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values t))))
               (loop for his-super in (ji::object-type-supertypes type)
                   do (do-one-type his-super)))))
    (let ((his-type (ji::basic-object-type process)))
      (do-one-type his-type))
    nil))

(defrule web-servers-are-vulnerable (:backward)
  then [vulnerable-to web-server-process buffer-overflow-attack]
  if t)

(defrule common-lisp-http-server-is-safe (:backward)
  then [protected-from cl-http-server-process buffer-overflow-attack]
  if t)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Indirect Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-indirectly
    :to-achieve [takes-control-of ?attacker ?victim-property ?victim]
    :plan (:goal [takes-indirect-control-of ?attacker ?victim-property ?victim]))

;;; Find an input of the victim and modify its contents
;;; probably should say that the behavior is affected by the content
;;; Fix modify
(defattack-method control-component-through-input
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :bindings ([input-of ?thing ?input])
    :plan (:goal [modify contents ?input])
    )


;;; want to say that if the property is affected by the size of the input
;;; then change the size of the input

;;; fix modify
(defattack-method control-component-through-input-size
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :prerequisites ([impacts size ?input ?victim-property ?victim])
    :bindings ([input-of ?victim ?input])
    :plan (:goal [modify size ?input])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Modification 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Note: Should this maybe be broken into two parts:
;;; 1) achieve ability to modify something
;;; 2) Modify it in a way that affects the victim's property
(defattack-method modify-through-part
    :to-achieve [modify ?victim-property ?victim]
    :typing ()
    ;; can't use the simpler notation here because a logic variable 
    ;; as the last component will fetch both parts and slots
    :bindings ([ltms:part-of ?victim ?component])
    :prerequisites ([impacts ?component-property ?component ?victim-property ?victim])
    :plan (:goal [modify ?component-property ?component])
    )

;;; modify a data-set by controlling a process that controls the data-set
(defattack-method modify-through-controller
    :to-achieve [modify ?victim-property ?victim]
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?controller process)
             (?victim data-set))
    :prerequisites ([process-controls-data-set ?controller ?victim])
    :plan (:sequential 
           (:goal [takes-control-of (controlled-data-set ?victim) ?controller])
           (:goal [use-control-of-to-affect-resource ?attacker ?controller ?victim-property ?victim])) 
    )

;;; NOTE: This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defattack-method modify-loadable-code
    :to-achieve [modify ?file-property ?object-file] 
    :bindings ((?source-file ?object-file.source-file))
    :typing ((?object-file dynamically-loadable-code-file))
    :plan (:sequential (:goal [modify code ?source-file])
                       (:goal [force-compilation ?attacker ?source-file ?object-file]))
    )

;;; Here ?user is again feedback to the caller about whose rights you got
;;; Is that different than ?foothold role ?
;;; Fix: Need two vesions.  IF ?foothold-role already has the access right
;;; then you do nothing.  Otherwise you go through achieve-access-right
;;; Partially fixed
(defattack-method modify-through-available-access-rights
    :to-achieve [modify ?object-property ?object]
    :bindings ((?computer ?object.machines)
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [current-foothold ?current-foothold-machine ?current-foothold-role])
    :typing ((?computer computer))
    ;; Use this only if you don't already have the required capability
    ;; (what if more than one capability implies the right?  Shouldn't
    ;; we check that he doesn't have any of them).
    :prerequisites ((not (has-relevant-capability ?current-foothold-role 'write ?object)))
    :plan (:sequential 
	   (:goal [achieve-access-right write ?object ?user])
	   (:action [use-access-right-to-modify ?attacker write ?user ?object]))
    )

(defattack-method modify-through-available-access-rights-when-have-then
    :to-achieve [modify ?object-property ?object]
    :bindings ((?computer ?object.machines)
	       [current-foothold ?current-foothold-machine ?current-foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?computer computer))
    ;; Use this only if you don't already have the required capability
    ;; (what if more than one capability implies the right?  Shouldn't
    ;; we check that he doesn't have any of them).
    :prerequisites ([has-permission ?current-foothold-role 'write ?object])
    :plan (:action [use-access-right-to-modify ?attacker write ?user ?object])
    )


;;; To increase the size of the active user set of some OS
;;; Find a user in the authorization pool for the OS
;;; and make that user a member of the active user set
(defattack-method modify-size-by-increase-size
    :to-achieve [modify size ?object]
    :plan (:goal [increase-size ?object])
    )

(defattack-method modify-active-user-set
    :to-achieve [increase-size ?active-user-set]
    :bindings ((?os-instance ?active.-user-set)
               (?authorization-pool ?os.-instance)
               (?user ?authorization-pool.users))
    :typing ((?active-user-set user-set)
             (?os-instance operating-system)
             (?authorization-pool authorization-pool)
             (?user user))
    :plan (:goal [make-member-of ?user ?active-user-set])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 
;;; Remote Execution
;;;
;;; Achieve-Remote-Execution is intimately bound up with get-foothold (i.e. lateral-motion)
;;; Get-foothold tries to find somebody that can made the desired connection
;;; and then tries to achieve remote execution of some kind on that machine
;;; But to achieve remote execution on that machine you need to get another foothold from
;;; which to launch the appropriate attack to get remote execution on the original foothold
;;;
;;; There are many ways of getting remote execution and so each of these will have a specific
;;; requirement for what protocol the new foothold machine will require to get to the target
;;; foothold i.e. if you're trying to get a remote shell then you'll need a foothold that can
;;; reach the target through either ssh or telnet.  If you're trying to take over a web server process
;;; then you'll need to find a machine that can speak http or https
;;; If there's some type of specific server with its own protocol then you'll need a foothold that 
;;; can reach the machine via that specific protocol.
;;;
;;; Foothold-role here is an output value that achieve-remote-execution is supposed to bind
;;; to either a user or a process
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Here foothold-role can be passed in unbound and will be unified with whoever you log in as
;;; There might be a more general way to organize this where there's a predicate (e.g. protocol-for-remote-execution)
;;; and a bunch of rules that takes a remote execution type and return a protocol name that's relevant for it.
;;; The reason for the rule is for example, remote shell cold be either ssh or telnet and by making it a rule
;;; we can generate them.

(defattack-method remote-execution-to-remote-shell
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-user]
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?victim-os ?victim-machine.os)
	       (?victim-user ?victim-os.users)
	       )
    :typing ((?victim-os operating-system)
             (?victim-user user)
	     (?victim-machine computer))
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [achieve-remote-shell ?victim-os ?victim-user])))

(defattack-method how-to-logon
    :to-achieve [achieve-remote-shell ?victim-os-instance ?victim-user]
    :bindings ((?victim-machine ?victim-os-instance.machine)
	       [current-foothold ?current-foothold-machine ?current-foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [protocol-for remote-execution remote-shell ?protocol])
    :typing ((?victim-os-instance operating-system)
	     (?victim-machine computer)
	     (?victim-user user))
    :plan (:sequential
	   (:goal [get-foothold ?victim-machine ?protocol])

           (:goal [achieve-knowledge-of-password ?attacker ?victim-user ?victim-machine])
           (:action [login ?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role]))
    )

;;; The stuff with noting place visited is there to prevet goal reduction loops
;;; We note that we've already tried to achieve execution on this machine and this
;;; produces a new context which is the context for achieving the goal
(defattack-method remote-execution-to-code-injection
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process]
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?os-instance ?victim-machin.os)
	       (?victim-process ?os-instance.processes))
    :typing ((?os-instance operating-system)
	     (?victim-process process))
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [achieve-code-injection ?victim-process ?os-instance])))

(defattack-method code-injection-against-process
    :to-achieve [achieve-code-injection ?process ?os-instance]
    :bindings ((?process ?os-instance.processes)
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?process web-server-process))
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-injection-attack ?process ?foothold-machine ?foothold-role])
    )

(defattack-method remote-execution-to-code-reuse
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process]
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?os-instance ?victim-machine.os)
	       (?victim-process ?os-instance.processes))
    :typing ((?os-instance operating-system)
	     (?victim-process process))
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution]) 
	   (:goal [achieve-code-reuse ?victim-process ?os-instance])))

(defattack-method code-reuse-against-web-server
    :to-achieve [achieve-code-reuse ?process ?os-instance]
    :bindings ([current-foothold ?foothold-machine ?foothold-role])
    :typing ((?process web-server-process))
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-reuse-attack ?process ?foothold-machine ?foothold-role])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance related specifics
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If somebody has goined direct control of the job-launcher
;;; They can affect performance by adding jobs
(defattack-method add-jobs-after-job-launcher-is-hacked
    :to-achieve [use-control-of-to-affect-resource ?attacker ?controller performance ?target]
    ;; note that here the short syntax works because ?controller is already bound
    :bindings ((job-admitter ?os.?controller)
               (?input ?os-instance.workload))
    :typing ((?controller os-job-admitter)
             (?os operating-system)
             (?input os-workload)
	     (?target process))
    :plan (:action [add-user-jobs ?attacker ?input])
    )

(defattack-method modify-job-request-queue
    :to-achieve [increase-size ?user-job-launch-queue]
    :bindings ((?user-job-launch-queue ?full-job-launch-queue.user-job-launch-request-queue)
               (?os-instance ?full-job-launch-queue.os)
	       (?full-job-launch-queue ?os-instance.job-launch-queue)
	       (?attacker-machine ?attacker.machines))
    :typing ((?user-job-launch-queue job-launch-request-queue)
             (?full-job-launch-queue os-job-launch-request-queue)
             (?os-instance operating-system)
	     (?attacker-machine computer))
    :plan (:sequential
           (:goal [achieve-remote-execution ?os-instance ?entity])
           (:repeated-action [submit-user-jobs ?entity ?user-job-launch-queue])))
    
;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defattack-method mung-in-core-data-structures
    :to-achieve [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set]
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?process process))
    :plan (:action [modify-in-core-data-structures ?process ?data-set ?foothold-machine ?foothold-role])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Methods for hacking access rights and gaining access
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Eventually we need to treat actions as real things that change the state
(defattack-method how-to-read-a-file
    :to-achieve [achieve-knowledge-of-contents ?file]
    :bindings ((?machine ?file.machines)
	       [attacker-and-machine ?attacker ?attacker-machine])
    :prerequisites ()
    :typing ((?file file))
    :plan (:sequential
	   (:goal [achieve-remote-execution ?victim-machine ?user])
           (:goal [achieve-access-right ?user read ?file ?privileged-user])
           (:action [read-with-rights-of ?attacker ?privileged-user ?file])
	   (:action [open-ftp-connection ?attacker ?attacker-machine])
	   (:action [trasmit-data ?attacker ?file ?attacker-machine])
	   ))

;;; If your foothold role already has the access rights
;;; do nothing
(defattack-method achieve-a-right-you-already-have 
    :to-achieve [achieve-access-right ?object ?right ?user]
    :bindings ([current-foothold ?foothold-machine ?foothold-role]
	       [unifiable ?user ?foothold-role])
    :prerequisites ([has-permission ?foothold-role ?object ?right])
    :plan ()
    )

;;; The ?user part of this is actually to feed back to the higher
;;; level that it should read the file with the access rights of the user
;;; but is that really necessary, why isn't the process enough

;;; Note that this approach would normally be used from a remote foothold
;;; That can reach whatever process you want, and such that this process can 
;;; then make a contact to the victim object.
;;; So the strategy would be to identify a process that runs on a machine that can reach the target
;;; and that has the accesss rights you need.
;;; Then figure out how to get to a foothold that can reach the process's machine
;;; then do this.

(defattack-method achieve-access-right-by-user-process-subversion
    :to-achieve [achieve-access-right ?right ?object ?user]
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ((?machine ?object.machines)
               (?os-instance ?machine.os)
               (?os-workload ?os-instance.workload)
               (?the-process ?os-workload.user-workload.processes)
               [runs-with-permissions-of ?the-process ?user]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?object computer-resource)
             (?machine computer)
             (?os-instance operating-system)
             (?os-workload os-workload)
             (?the-process process))
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process])
	   (:action [uses-control-to-achieve-access-right ?attacker ?right ?object ?foothold-machine]))
    )

(defattack-method achieve-access-right-by-server-process-subversion
    :to-achieve [achieve-access-right ?right ?object ?user]
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ((?machine ?object.machines)
               (?os-instance ?machine.os)
               (?os-workload ?os-instance.workload)
               (?the-process ?os-workload.server-workload.processes)
               [runs-with-permissions-of ?the-process ?user]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [current-foothold ?foothold-machine ?foothold-role]
               )
    :typing ((?object computer-resource)
             (?machine computer)
             (?os-instance operating-system)
             (?os-workload os-workload)
             (?the-process process)           
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process])
	   (:action [uses-control-to-achieve-access-right ?attacker ?right ?object ?foothold-machine]))
    )

(defattack-method how-to-achieve-access-right-by-remote-shell-on-target
    :to-achieve [achieve-access-right ?right ?object ?other-user]
    :bindings ((?machine ?object.machines)
               (?os-instance ?machine.os)
	       (?pool ?os-instance.authorization-pool)
	       [current-foothold ?foothold-machine ?foothold-role]
	       (?foothold-os ?foothold-machine.os)
	       (?other-user ?pool.users))
    :typing ((?object computer-resource)
             (?machine computer)
             (?os-instance operating-system)
	     (?pool authorization-pool)
             (?other-user user))
    ;; Note: has-capability is a function not an assertion
    :prerequisites ([has-permission ?other-user ?right ?object])
    :plan (:goal [achieve-remote-shell ?foothold-os ?other-user])
    )

;;;;;; Note & Fix: This calls itself recursively but has no protection against
;;;;;; ping-ponging
;;;(defattack-method how-to-achieve-access-right-by-remote-shell-indirectly
;;;    :to-achieve [achieve-access-right ?attacker ?right ?object ?user ?foothold-machine ?foothold-role]
;;;    :bindings ([ltms:value-of (?object machines) ?machine]
;;;               [ltms:named-part-of ?machine os ?os-instance]
;;;               [requires-access-right ?object ?right ?capability]
;;;	       [ltms:value-of (?os-instance authorization-pool) ?pool]
;;;	       [ltms:value-of (?pool users) ?user]
;;;	       ;; all this is about finding another machine in the enclave
;;;	       [ltms:value-of (?machine site) ?site]
;;;	       [ltms:value-of (?site enterprise) ?enterprise]
;;;	       [ltms:value-of (?enterprise sites) ?other-site]
;;;	       [ltms:value-of (?other-site subnets) ?other-subnet]
;;;	       [ltms:value-of (?other-subnet computers) ?other-machines]
;;;	       [ltms:named-part-of ?other-machine os ?other-os]
;;;	       )
;;;    :typing ([ltms:object-type-of ?object computer-resource]
;;;             [ltms:object-type-of ?machine computer]
;;;             [ltms:object-type-of ?os-instance operating-system]
;;;	     [ltms:object-type-of ?pool authorization-pool]
;;;             [ltms:object-type-of ?user user])
;;;    ;; Note: has-capability is a function not an assertion
;;;    :PREREQUISITES ((not (eql ?other-machines ?machine))
;;;		    [reachable-from ?machine ?other-machine ?]
;;;		    [reachable-from ?other-machine ?attacker ?]
;;;		    (has-capability ?user ?capability)
;;;		    (break "~a ~a ~a" ?user ?other-machine ?other-os))
;;;    :plan (:goal [achieve-remote-execution ?attacker ?user ?other-os ?foothold-machine ?foothold-role])
;;;    )




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Active User Set and Logging in 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method join-active-user-set
    :to-achieve [make-member-of ?user ?active-user-set]
    :bindings ((?os-instance ?active-user-set.os))
    :typing ((?active-user-set user-set)
             (?os-instance operating-system))
    :plan (:goal [achieve-remote-shell ?os-instance ?user])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Passwords and secrets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method user-knows-own-password
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :guards ([unifiable ?attacker ?user])
    :plan (:action [use-own-password ?user ?victim-machine])
    )
            
(defattack-method how-to-get-password-by-guessing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :guards ([not [unifiable ?attacker ?user]])
    :plan (:goal [guess-password ?attacker ?user ?victim-machine])
    )

(defattack-method guess-typical-user
    :to-achieve [guess-password ?attacker ?user ?victim-machine]
    :guards ([is-typical-user ?user])
    :typing ((?user user)
	     (?attacker attacker))
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?victim-machine])
    )

(defattack-method guess-superuser-passwords
    :to-achieve [guess-password ?attacker ?user ?victim-machine]
    :bindings ((?machine ?user.machines)
	       (?user  ?machine.os.superuser))
    :typing ((?user user)
	     (?machine computer))
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?victim-machine])
    )

(defattack-method get-sysadmin-password-by-bricking
    :to-achieve [achieve-knowledge-of-password ?attacker ?victim-user ?victim-machine]
    :guards ([is-superuser ?victim-os ?victim-user])
    :bindings ((?victim-machine ?victim-user.machines)
	       (?victim-os ?victim-machine.os)
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?victim-user user)
	     (?victim-machine computer))
    :plan (:sequential
	    (:goal [install-malware ?attacker ?victim-machine key-logger])
	    (:goal [brick-machine ?attacker ?victim-machine])
	    (:action [capture-password-through-keylogger ?attacker ?victim-user ?victim-machine])
	    ))

(defattack-method brick-machine-by-kill-disk
    :to-achieve [brick-machine ?attacker ?victim-machine]
    :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role])
    :plan (:sequential
	   (:goal [install-malware ?attacker ?victim-machine kill-disk])
	   (:action [fill-disk ?attacker ?victim-machine kill-disk])
	   ))

;;; This is a stub
(defattack-method how-to-install-malware
    :to-achieve [install-malware ?attacker ?victim-machine ?malware-type]
    :prerequisites ()
    :plan (:action [install-malware ?attacker ?malware-type ?victim-machine]))


;note: need plan for install malware

;;; Fix This:
;;; To pull off a phishing attack:
;;;  The attacker must have a foothold for the email server of the victim-user
;;;  
(defattack-method how-to-get-password-by-phishing
    :to-achieve [achieve-knowledge-of-password ?attacker ?victim-user ?victim-machine]
    :bindings ([email-client-of ?victim-user ?process]
	       (?attacker-machine ?attacker.machines)
	       (?os-instance ?process.host-os)
	       (?email-server-machine ?os-instance.machine)
	       )
    :typing ((?victim-user user)
	     (?process email-server-process)
	     (?os-instance operating-system)
             (?email-server-machine computer)
	     (?attacker-machine computer))
    :plan (:sequential
           (:goal [get-foothold ?email-server-machine smtp])
           (:action [phishing-attack ?attacker ?email-server-machine ?victim-user ?process]))
    :post-conditions ([current-foothold ?current-foothold-machine ?current-foothold-role])
    )


; This stuff was in the thing above, but I'm not sure what it was trying to say

; ((:goal (know (password ?user)) 
; 	:plan ((:goal (sniff (password ?user))
; 		      :plan ((:goal (achieve-email-connection-to ?os-instance) 
; 				    :plan ?plan)
; 			     )))))

(defattack-method how-to-get-password-by-sniffing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :typing ((?user user)
             (?victim-machine computer)
             (?subnet subnet))
    :bindings ((?subnet ?victim-machine.subnets))
    :plan (:parallel 
           (:goal [observe-network-traffic ?attacker ?subnet])
           (:action [sniff-a-password ?attacker ?user ?subnet]))
    )

 ; ((:goal (know (password ?user)) 
 ; 	 :plan (?observation-plan 
 ; 		(:action (sniff-a-passward ?user ?subnet)))))

;;; to be filled in: you can get his password by external sniffing of unsecured protocols
;;; such as smtp, pop

;;; ((:goal (connect ?machine) :plan ((:action (connect-via ?protocol-name ?machine)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Lateral Motion
;;; If the attacker is trying to achieve a connection to a target machine "A" using some specific protocol
;;; There are two cases:
;;; 1) The attacker can reach A from its current position
;;; 2) The attacker can't reach A using that protocol from its current position.
;;;    In this case the attacker follows this strategy
;;;    a) Find a machine B that can make the intended connection 
;;;    b) Get some form of remote execution on B
;;;    c) Have B make the connection to A
;;;    Achieving remote execution on B, however, may not be directly achievable
;;;    Because that requires connecting to B from the attacker's position using
;;;    whatever protocol is relevant for the exploit that allow remote execution
;;;    So the operator that achieves remote execution on B may need to get a foothold
;;;    on some machine C that can reach B, and so on recursively.
;;;    
;;;    One thing that complicates this reasoning is that when B isn't directly reachable and the attacker tries
;;;    to find a foothold to B (which was the foothold to get to A), we might discover that A could serve as the foothold
;;;    to B.  But then we'd be in an infinite goal descent.
;;; So to prevent this we do something hokey:
;;; 1) We put a guard on the operator, saying that it's only valid if it hasn't already been visited
;;; 2) We add a "note" in the plan saying that we should note that we've visited this place
;;;
;;; Corresponding to the two cases there are two methods
;;; There are two attack-methods: 
;;; From the easy case (1):  Direct-Foothold
;;; For the hard caser (2): Lateral-motion
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Direct Method, applicable when you can get from your current foothold to the target-machine 
;;; so the foothold is the where this step is taking place from and the role is the attacker
(defattack-method direct-foothold
    :to-achieve [get-foothold ?victim-machine ?protocol-name]
    :guards ([not [place-already-visited? ?victim-machine foothold]])
    :bindings ((?victim-os ?victim-machine.os)
	       [current-foothold ?current-foothold-machine ?current-foothold-role])
    :typing ((?victim-os operating-system)
	     (?victim-machine computer)
	     (?current-foothold-machine computer))
    :prerequisites ([accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?protocol-name])
    )

(defattack-method lateral-motion
    :to-achieve [get-foothold ?victim-machine ?protocol-name]
    :guards ([not [place-already-visited? ?victim-machine foothold]]
	     [not [foothold-exists ?victim-machine]]
	     ;; Use this method only if you can't get a connection to the victim from where you are
	     [not [accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine]])
    :bindings ((?victim-os ?victim-machine.os)
	       ;; Now find somebody that can make the connection, accepts connection will find one if there is one
	       [current-foothold ?current-foothold-machine ?current-foothold-role]
	       [accepts-connection ?victim-machine ?protocol-name ?new-foothold-machine]
	       )
    :typing ((?victim-os operating-system)
	     (?victim-machine computer)
	     (?current-foothold-machine computer)
	     )
    :plan (:sequential
	   ;; Make a note that we've already considered this place as a foothold to
	   ;; prevent looping back to here while trying to achieve remote execution
	   (:note [place-visited ?victim-machine foothold])
	   ;; Now see if the attacker can gain remote execution on the new-foothold-machine and in what role 
	   ;; (?new-foothold-role is a return value)
	   (:goal [achieve-remote-execution ?new-foothold-machine ?new-foothold-role])
	   ;;If so then actually make the connection to the victim from the new foothold
	   ;; (:goal [make-connection ?victim-os-instance ?protocol-name ?remote-execution-state ?output-contet])
	   )
    :post-conditions ([has-foothold ?new-foothold-machine ?new-foothold-role foothold]))




;;; to be filled in:
;;; if a remote request for a service arrives
;;; and the machine runs that service
;;; and the server admittance policy allows it
;;; then an instance of that server process is created
;;; this instance is part of the server workload
;;; it runs with the permissions of that server process type.

;;; if a user is logged in
;;; and the user requests a job to be started
;;; and if the user job admitter allows it
;;; then an instance of a user process is started
;;; it runs with the permission of the user 


;;; These next several sections really are just knowledge rules
;;; not rules about attacking

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network Traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method control-the-network-stack
    :to-achieve [takes-direct-control-of ?attacker ?stack-property ?network-stack]
    :bindings ((?network-stack ?os-instance.network-monitor)
               (?superuser ?os-instance.superuser)
	       (?attacker-machine ?attacker.machines))
    :typing ((?network-stack network-stack)
             (?os-instance operating-system)
	     (?attacker-machine computer)
             (?superuser user))
    :plan (:sequential 
           (:goal [achieve-remote-shell ?os-instance ?superuser])
           (:action [control ?attacker ?network-stack ?attacker-machine]))
    )

(defattack-method read-network-traffic
    :to-achieve [observe-network-traffic ?attacker ?subnet]
    :bindings ((?switch ?subnet.switch)
               (?os ?switch.os)
               (?network-stack ?os.network-monitor))
    :typing ((?subnet switched-subnet)
             (?switch switch)
             (?network-stack network-stack))
    :plan (:sequential 
	   (:goal [takes-direct-control-of ?attacker network-traffic ?network-stack ])
	   (:action [observe ?attacker network-traffic ?subnet]))
    )



#|

Notes:

There are several cases where you want to get knowledge of something (e.g. a password)
and then use it later.  This can be dealt with either by careful
modularization which might be far too tricky, or by having a general
model that only runs rules on achieve-knowledge-of if there is no
predicate promising the thing is known.





This is redundant

(defrule get-knowledge-of-through-available-access-rights (:backward)
  then [achieve-knowledge-of ?attacker ?object ((:goal (know-contents-of ?object) 
                                                 :plan ?composite-plan))]
  ;; assumption is that we know the object
  if [and [ltms…:object-type-of ?object computer-resource]
	  [ltms:value-of (?object machines) ?computer]
          [ltms:object-type-of ?computer computer]
          [part-of (?computer os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
          [requires-access-right ?object read ?capability]
	  [achieve-access-right ?attacker read ?object ?vehicle ?access-plan]
	  (unify ?composite-plan 
                 (append ?access-plan 
                         `((:action (read-using-process-capability ,?capability ,?vehicle ,?object)))))
          ])


Residencies
Formats: source, class, jar in-core-code
Transformations: compilation jarification loading


|#

; Idea picked up at MRC PI Mtg
; Attacker let's lose a shit-storm with low value but high response cost
; Then uses the opportunity created by the diversion of attention to 
; launch a high-value but perhaps more risky attack.
;;;
;;; Knowledge of memory contents as pre-requisite to overwriting attacks
;;; Memory disclosure attacks as way to gain knowledge of memory contents
;;;  Ability to read memory as pre-requisite to that
;;;    Privilege escalation as way to that
;;;    Buffer overread as read to do that
;;; Having copy of system as way to have knowledge of memory contents



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Things relevant to control systems
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If you want to affect the accuracy of a control process
;;; find it's sensors and then find a bus (or network) that
;;; those sensors are on and that the control process is also on
;;; the find another process that is also on that bus
;;; and send fake sensor data reports for that sensor to the control process


(defattack-method fake-sensor-data
    :to-achieve [affect accuracy ?controller-process]
    :bindings ((?controller-machine ?controller-process.machines)
	       ;; does that machine play the part of a controller in some control system
	       [system-role ?system controller ?controller-machine]
	       ;; if so find a sensor in that same system
	       [system-role ?system sensor ?sensor-machine]
	       ;; and a bus that both the sensor and the controller are on
	       [connected-to ?sensor-machine ? ?bus ?]
	       [connected-to ?controller-machine ? ?bus ?]
	       ;; now find a another (or the same) machine that's on that bus
	       [connected-to ?victim-machine ? ?bus ?]
	       ;; then find a process runnning on that machine
	       (?victim-os ?victim-machine.os)
	       )
    :prerequisites ([output-of ?sensor-machine ?signal]
		    ;; the output of the sensor must be an input to 
		    ;; the controller process
		    [input-of ?controller-process ?signal]
		    [or [can-be-mastered-by ?controller-machine ?victim-machine ?bus]
			(equal ?controller-machine ?victim-machine)]
		    )
    :typing ((?controller-machine computer)
	     (?victim-machine computer)
	     (?controller-process control-system-process)
	     (?system system)
	     (?sensor-machine computer)
	     (?signal sensor-signal)
	     (?bus unmastered-medium)
	     (?victim-os operating-system)
	     )
    :plan (:sequential
	   ;; You have to specify what the entity here is
	   ;; it can either be a user or a process
	   ;; shouldn't really be in the operators that detemine how to do the remote execution
	   (:goal [achieve-remote-execution ?victim-machine ?entity])
	   ;; issue a false sensor data report to the controller from the attacker machine over the bus
	   ;; of the sensor type 
	   (:action [issue-false-sensor-data-report ?controller-machine ?victim-machine ?bus ?signal]))
    )

; (defattack-method fake-command-data
;     :to-achieve [affect ?attacker accuracy ?controller-process]
;     :bindings ([ltms:value-of (?controller-process machines) ?machine]
; 	       [connected-to-bus ?machine ?interface ?bus ?slot]
; 	       [connected-to-bus ?other-machine ?other-interface ?bus ?other-slot]
; 	       [ltms:named-part-of ?other-machine os ?os])
;     :prerequisites ((not (eql ?machine ?other-machine))
; 		    [can-be-mastered-by ?machine ?other-machine ?bus])
;     :typing ([ltms:object-type-of ?machine computer]
; 	     [ltms:object-type-of ?other-machine computer]
; 	     [ltms:object-type-of ?os operating-system]
; 	     [ltms:object-type-of ?bus bus])
;     :plan (:sequential
; 	   (:goal [remote-execution ?attacker ?entity ?os])
; 	   (:action [issue-incorrect-setpoint ?attacker ?machine ?other-machine ?bus]))
;     )
 
(defattack-method sensor-injection-attack
    :to-achieve [affect data-integrity ?signal]
    :bindings ((?machine ?signal.machines)
	       [attacker-and-machine ?attacker ?attacker-macine])
    :prerequisites ([system-role ?system sensor ?machine]
		    [is-proximate-to ?attacker ?victim radio])
    :typing ((?machine computer)
	     (?signal sensor-signal)
	     (?system system))
    :plan (:action [signal-noise-injection ?attacker ?machine ?signal])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Quick hack for botnet recruitment ala Mirai
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method recruit-to-mirai-botnet
    :to-achieve [affect independence ?cycle-pool]
    :bindings ((?victim-machine ?cycle-pool.machines)
	       (?victim-os ?cycle-pool.os)
	       [attacker-and-machine ?attacker ?attacker-macine]
	       )
    :plan (:sequential
	   (:action [port-scan ?attacker ?victim-machine ?attacker-machine telnet-ports])
	   (:goal [get-foothold ?victim-machine telnet ?input-context ?foothold-context])
	   (:action [login ?attacker white-list-member ?victim-os ?foothold-machine])
	   (:action [download-malware-from-source ?attacker ?foothold-machine ?victim-machine mirai-client]))
    )
		    