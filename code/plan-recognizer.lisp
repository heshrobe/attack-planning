;;; -*- mode: fi:common-lisp; package: aplan; readtable: Joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Parameters for making a stripped down data file with only the fields useful for
;;; attack-plan recognition1
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *keep-keys* '("srcip" "sport" "dstip" "dsport" "dur" "service" "Stime" "Ltime" "is_ftp_login" "attack_cat" "Label"))
  (defparameter *new-keys* '("attack_subcat"))
  (defparameter *all-keys* (append *keep-keys* *new-keys*))
  (defparameter *data-file* #p"rp:chase;unsw-nb15_1.csv")
  (defparameter *key-file* #p"rp:chase;unsw-nb15_features.csv")
  (defparameter *subset-file* #p"rp:chase;unsw-nb15_subset.csv")
  (defparameter *gt-file* #p"rp:chase;unsw-nb15_gt.csv")
  (defparameter *merged-file* #p"rp:chase;unsw-nb15_merged.csv")
  (defparameter *event-file* #p"rp:chase;event-trace.csv")
  (defparameter *test-file* #p"rp:chase;test-file.csv")
  (defparameter *intermediate-file* #p"rp:chase;intermediate-file.csv")
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Map-records and Get-Position-Map
;;;
;;; Key-location is optional and defaults to :in-file
;;; If provided the value must be either :in-file or a pathname
;;; If it's a pathname, the file at that pathname contains a set of lines
;;; each with 2 entries: the key-name and its position in the csv lines
;;; of the other file
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun whitespace-char-p (char)
  (and (characterp char)
       (or (char-equal char #\Space)
	   (eql char #\Tab))))

(defun map-records (pathname keys callback &key (key-location :in-file))
  (let* ((answer-positions (get-position-map pathname :key-location key-location))
	 (entry-vector (make-array 5 :adjustable t :fill-pointer 0))
	 (answer-vector (make-array (length keys)))
	 )
    (with-open-file (f pathname :direction :input)
      (when (eql key-location :in-file)
	(read-line f))			;skip over header line
      (loop for entry-line = (read-line f nil 'eof)
	  for lines-read from 1
	  until (eql entry-line 'eof)
	  for processed-line = (process-csv-line entry-line :vector entry-vector)
	  do (loop for key in keys
		 for index from 0
		 for position = (rest (assoc key answer-positions :test #'string-equal))
		 for value = (aref processed-line position)
		 do (setf (aref answer-vector index) value))
	  unless (whitespace-char-p (aref entry-line 0))
	  do (funcall callback answer-vector entry-line)))))

(defun get-position-map (pathname &key (key-location :in-file))
  (cond
   ((eql key-location :in-file)
    (let* ((header-line (with-open-file (f pathname) (read-line f)))
	   (header-vector (process-csv-line header-line :vector (make-array 20 :adjustable t :fill-pointer 0)))
	   (alist (loop for key across header-vector
		      for i from 0
		      collect (cons key i))))
      alist))
   (t
    (with-open-file (f key-location :direction :input)
      (read-line f)			;get rid of header in this file
      (loop with vector = (make-array 6 :adjustable t :fill-pointer 0)
	  for next-line = (read-line f nil 'eof)
	  until (eql next-line 'eof)
	  do (process-csv-line next-line :vector vector)
	  collect (cons (aref vector 1) (1- (read-from-string (aref vector 0)))))))))

(defun process-csv-line (line &key (size 80) (vector (make-array size :adjustable t :fill-pointer 0)))
  (setf (fill-pointer vector) 0)
  (loop for last-delimiter-pos = -1 then next-delimiter-pos
      for next-delimiter-pos = (position #\, line :start (1+ last-delimiter-pos))
      for next-element = (string-trim '(#\space #\tab #\newline #\return)
				      (subseq line (1+ last-delimiter-pos) next-delimiter-pos))
      do (vector-push-extend next-element vector)
      until (null next-delimiter-pos))
  vector)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;
;;; Mapping records macro
;;; (map-records
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun lispify (string)
    (if (string-equal string "") nil
      (intern
       (string-upcase (substitute-if-not  #\- #'alphanumericp string))))))

(defmacro with-mapped-records ((pathname keys &key vector line (key-location :In-file)) &body body)
  (when (symbolp keys) (setq keys (symbol-value keys)))
  (let* ((answer-vector-symbol (or vector (gentemp (string-upcase "vector"))))
	 (line-symbol (or line (gentemp (string-upcase "line"))))
	 (bindings
	  (loop for key in keys
	      for key-symbol = (lispify key)
	      for index from 0
	      collect `(,key-symbol (aref ,answer-vector-symbol ,index)))))
    `(map-records ,pathname ',keys
		 #'(lambda (,answer-vector-symbol ,line-symbol)
		     (declare (ignorable ,line-symbol))
		     (let ,bindings
			(declare (ignorable ,@(loop for (symbol) in bindings collect symbol)))
			,@body)
		     :key-location ,key-location))))

;;; This is a version that you can use in an external function
;;; called my map-records.
(defmacro with-fields ((used-fields &key vector all-fields) &body body)
  (when (symbolp used-fields) (setq used-fields (symbol-value used-fields)))
  (when (and all-fields (symbolp all-fields)) (setq all-fields (symbol-value all-fields)))
  (let* ((answer-vector-symbol (or vector (gentemp (string-upcase "vector"))))
	 (bindings
	   (loop for field in all-fields
	       for index from 0
	       when (member field used-fields :test #'string-equal)
	       collect `(,(lispify field) (aref ,answer-vector-symbol ,index)))))
    `(let ,bindings
       (declare (ignorable ,@(loop for (symbol) in bindings collect symbol)))
       ,@body)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Various uses
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun get-category-map (pathname)
  (let ((hash-table (make-hash-table :test #'equal)))
    (with-mapped-records (pathname ("Attack Category" "Attack subcategory"))
      (let* ((entry (gethash attack-category hash-table)))
	(unless entry
	  (setf (gethash attack-category hash-table) nil))
	(pushnew attack-subcategory (gethash attack-category hash-table))))
    hash-table))


(defun get-all-ips (pathname key-location)
  (let ((ips nil))
    (with-mapped-records (pathname ("srcip" "dstip") :key-location key-location)
      (pushnew srcip ips :test #'string-equal)
      (pushnew dstip ips :test #'string-equal)
      )
    (cluster-ip-addresses (loop for ip in ips collect (create-ip-address ip)))))

(defun get-attacker-ips (pathname key-file)
  (let ((ips nil))
    (with-mapped-records (pathname ("srcip" "label") :key-location key-file)
      (let ((label-value (read-from-string label)))
	(when (not (zerop label-value))
	  (pushnew  srcip ips :test #'string-equal))))
    (cluster-ip-addresses (loop for ip in ips collect (create-ip-address ip)))))

(defun get-victim-ips (pathname key-file)
  (let ((ips nil))
    (with-mapped-records (pathname ("dstip" "label") :key-location key-file)
      (let ((label-value (read-from-string label)))
	(when (not (zerop label-value))
	  (pushnew  dstip ips :test #'string-equal))))
    (cluster-ip-addresses (loop for ip in ips collect (create-ip-address ip)))))

(defun display-address-table (hash-table &optional (stream *standard-output*))
  (loop for address being the hash-keys of hash-table using (hash-value count)
      collect (list (create-ip-address address) count) into entries
      finally (clim:formatting-table (stream)
		(clim:formatting-row (stream)
		  (clim:formatting-cell (stream :align-x :center) (write-string "Address" stream))
		  (clim:formatting-cell (stream :align-x :center) (write-string "Count" stream)))
		(loop for (address count) in (sort entries #'< :key #'(lambda (pair) (ip-address-integer (first pair))))
		    do (clim:formatting-row (stream)
			 (clim:formatting-cell (stream :align-x :left)
			   (write-string (ip-address-string address) stream))
			 (clim:formatting-cell (stream :align-x :right)
			   (format stream "~d" count)))))
	      (return entries)))

(defun cluster-ip-addresses (address-list)
  (let ((cluster-ht (make-hash-table :test #'equal)))
    (loop for address in address-list
	for octet1 = (octet1 address)
	for octet2 = (octet2 address)
	for octet3 = (octet3 address)
	for octet4 = (octet4 address)
	for key = (list octet1 octet2 octet3)
	for entry = (gethash key cluster-ht)
	unless entry
	do (setf (gethash key cluster-ht) nil)
	;; do (format t "~%~a ~a ~a" address key octet4)
	do (pushnew octet4 (gethash key cluster-ht)))
    (loop for key being the hash-keys of cluster-ht using (hash-value value)
	do (setf (gethash key cluster-ht) (sort value #'<)))
    cluster-ht))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Collecting all possible values for some specific set of keys
;;;  The set of keys is passed in dynamically
;;;  So I can't use the macro here because the set of keys isn't
;;; known at compile time
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun collect-values (pathname keys &key key-location)
  (with-open-file (f pathname :direction :input)
    (let* ((answers (loop for key in keys collect (list key nil))))
      (map-records pathname keys :key-location key-location
		   #'(lambda (vector line)
		       (declare (ignore line))
		       (loop for key in keys
			   for index from 0
			   for value = (aref vector index)
			   for answer-entry = (assoc key answers :test #'string-equal)
			   do (pushnew value answer-entry :test #'string-equal)))
		   :key-location key-location
		   ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Subset-file
;;;
;;; Builds a new csv file with only a subset of the values in each line of the original csv file
;;; Key-subset is the set of keys from the original file to preserve
;;; New-Keys is a set of new keys to add to the output file (without values)
;;; The output csv file will always have a header line with all the keys
;;; Key-location is as for map-records
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun subset-file (input-file key-subset new-file new-keys &key key-location)
  (with-open-file (out new-file :direction :output :if-does-not-exist :create :if-exists :supersede)
    (format out "~{~a~^, ~}" (append key-subset new-keys))
    (map-records input-file key-subset
		 #'(lambda (vector line)
		     (declare (ignore line))
		     (let ((all-values (append (coerce vector 'list)
					       (loop for key in new-keys collect ""))))
		       (format out "~%~{~a~^, ~}" all-values)))
		 :key-location key-location
		 )))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dealing with Unix Time vs Universal Time
;;; Both count in seconds just with different base times
;;;
;;; Timestamps in the file are "Unix Timestamps" i.e. seconds since
;;; 1/1/1970.
;;;
;;; Common Lisp Universal time is the number of seconds since
;;; midnight, January 1, 1900 GMT (ignoring leap seconds).
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *unix-time-stamp-offset* (encode-universal-time 0 0 0 1 1 1970 0))

(defun unix-time-to-ut (unix-time) (+ *unix-time-stamp-offset* unix-time))
(defun ut-to-unix-time (ut) (- ut *unix-time-stamp-offset*))

(defun decode-unix-time (unix-time)
  (decode-universal-time (+ *unix-time-stamp-offset* unix-time)))

(defun format-unix-time (unix-time &optional (stream *standard-output*))
  (multiple-value-bind (second minute hour day month year time-zone) (decode-unix-time unix-time)
    (declare (ignore time-zone))
    (format stream "~2,'0d\:~2,'0d\:~2,'0d ~d/~d/~d"
	    second minute hour
	    month day year)))

(defun formatted-unix-time (Unix-time-string)
  (format-unix-time (read-from-string Unix-time-string) nil))

(defparameter stime 1421927377)
(defparameter etime 1421955842)

;;; Finding the span of time represented in the file
(defun find-time-range (file &key (key-location *key-file*))
  (let ((low nil) (high nil))
    (with-mapped-records (file ("stime" "ltime") :key-location key-location :line line)
      (let ((his-start-time (read-from-string stime))
	    (his-end-time (read-from-string ltime)))
	(when (or (not (numberp his-start-time))
		  (not (numberp his-end-time)))
	  (break "~a" line))
	(when (or (Null low) (< his-start-time low))
	  (setq low his-start-time))
	(when (or (Null high) (> his-end-time high))
	  (setq high his-end-time))))
    (values low high)))

;;; finding all records that occur within a time range
(defun find-records-in-time (file start-time end-time &key (key-location *key-file*))
  (let ((answers nil))
    (with-mapped-records (file ("stime" "ltime") :key-location key-location :line line)
	(let ((his-start-time (read-from-string stime))
	      (his-end-time (read-from-string (rest ltime))))
	  (when (or (< start-time his-start-time end-time)
		    (< start-time his-end-time end-time))
	    (push (copy-seq line) answers)))
    answers)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dumping actions in format of compressed file
;;;
;;; Record Format:
;;; srcip, sport, dstip, dsport, dur, service, Stime, Ltime, is_ftp_login, attack_cat, Label, attack_subcat
;;; Label is one of Fuzzers, Reconnaissance, Shellcode, Analysis, Backdoors,
;;;                 DoS, Exploits, Generic, Worms, or blank
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun dump-action-sequence (sequence &key (start-time 0) (end-time 0) (file nil file-p))
  (flet ((do-it (stream)
	   (loop with duration = (- end-time start-time)
	       with random-bound = (floor duration (length sequence))
	       for action in sequence
	       for random-duration = (floor (random random-bound))
	       for time = start-time then (+ next-start-time random-duration)
	       for name = (action-name action)
	       for next-start-time = (ceiling (dump-action name action time stream)))))
    (if file-p
	(with-open-file (f file :direction :output :if-exists :supersede :if-does-not-exist :create)
	  (do-it f))
      (do-it *standard-output*)))
  (values))

;;; Should return end-time
(defgeneric dump-action (action-type action start-time &optional stream))

;;; for debugging, print out what we don't know.
(defmethod dump-action (type (action action) start-time &optional (stream *standard-output*))
  (format stream "~%I don't yet know how to dump ~a actions with args ~{~a~^, ~}" type (arguments action))
  start-time)

;;; Connect-via: current-foothold-computer current-foothold-role victim-computer protocol-name)
(defmethod dump-action ((type (eql 'connect-via)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (source foothold-role destination protocol) (arguments action)
    (declare (ignore foothold-role))
    (let* ((port (first (ports-for-protocol protocol)))
	   (srcip (ip-address-string (first (ip-addresses source))))
	   (dstip (ip-address-string (first (ip-addresses destination))))
	   (duration 2)
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0 "" 0 "")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'guess-password)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (attacker user victim-computer) (arguments action)
    (declare (ignore attacker user))
    (let* ((port 0)
	   (protocol 0)
	   (srcip (ip-address-string (first (ip-addresses victim-computer))))
	   (dstip srcip)
	   (duration (* 2 60))
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0 "Exploits" 1 "Password Guess")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'login)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (victim-user victim-os-instance current-foothold-computer current-foothold-role) (arguments action)
    (declare (ignore current-foothold-role current-foothold-computer))
    (let* ((port 0)
	   (protocol 0)
	   (victim-computer (computer victim-os-instance))
	   (srcip (ip-address-string (first (ip-addresses victim-computer))))
	   (dstip srcip)
	   (duration 30)
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "Login" 0 (string (name victim-user)))))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'download-software)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (package source-computer destination-computer role) (arguments action)
    (declare (ignore package role))
    (let* ((port (first (ports-for-protocol 'ftp)))
	   (protocol "ftp")
	   (srcip (ip-address-string (first (ip-addresses source-computer))))
	   (dstip (ip-address-string (first (ip-addresses destination-computer))))
	   (duration (* 5 60))
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "Download" 1 "Malware Download")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'load-software)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (package computer) (arguments action)
    (declare (ignore package))
    (let* ((port 0)
	   (protocol 0)
	   (srcip (ip-address-string (first (ip-addresses computer))))
	   (dstip srcip)
	   (duration 30)
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "load" 1 "Malware load")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'fill-disk)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (attacker computer exploit) (arguments action)
    (declare (ignore attacker exploit))
    (let* ((port 0)
	   (protocol 0)
	   (srcip (ip-address-string (first (ip-addresses computer))))
	   (dstip srcip)
	   (duration (* 30 60))
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "Bricking" 1 "Disk Filled")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'capture-password-through-keylogger)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (attacker victim-user victim-computer) (arguments action)
    (declare (ignore attacker))
    (let* ((port 0)
	   (protocol 0)
	   (srcip (ip-address-string (first (ip-addresses victim-computer))))
	   (dstip srcip)
	   (duration (* 10 60))
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "Keylogger" 1 (string (name victim-user)))))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

(defmethod dump-action ((type (eql 'use-access-right-to-modify)) (action action) start-time &optional (stream *standard-output*))
  (destructuring-bind (attacker action whose-right foothold-computer victim-object victim-computer) (arguments action)
    (declare (ignore attacker action whose-right victim-object))
    (let* ((port (first (ports-for-protocol 'database-protocol)))
	   (protocol "database")
	   (srcip (ip-address-string (first (ip-addresses foothold-computer))))
	   (dstip (ip-address-string (first (ip-addresses victim-computer))) )
	   (duration (* 10 60))
	   (end-time (+ start-time duration))
	   (record (list srcip port dstip port duration protocol start-time end-time 0  "Database-Access" 0 "Write")))
      (format stream "~%~{~a~^, ~}" record)
      end-time)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Merging Action Sequence with Background traffic
;;;  Background traffic is in a subset file with a header line
;;;  Action sequence is in a csv file without a header but with the same fields
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; The initial file isn't sorted by start time
;;; so doing a merge isn't possible without first sorting the big file
;;; Instead I just do a stupid thing of just appending the two files
;;; (could I have just called cat as a shell command

(defun append-files (f1 f2 out)
  (with-open-file (of out :direction :output :if-exists :supersede :if-does-not-exist :create)
    (flet ((copy-records (pathname)
	     (with-open-file (f pathname :direction :input)
	       (loop for line = (read-line f nil 'eof)
		   until (eql line 'eof)
		   do (write-line line of)))))
      (copy-records f1)
      (copy-records f2))))

;;; Then I sort them by reading in everything in the appended files
;;; and then calling sort

(defun sort-file (in-pathname output-pathname)
  (let ((records (make-array 70000 :fill-pointer 0 :adjustable t)))
    (format t "~%Reading records")
    (with-mapped-records (in-pathname ("stime") :key-location :in-file :line line)
      (let ((time (read-from-string stime)))
	(vector-push-extend (list time line) records)))
    (format t "~%Sorting records")
    (sort records #'< :key #'first)
    (format t "~%Writing records")
    (let ((first-line (with-open-file (f in-pathname :direction :input) (read-line f))))
      (with-open-file (out output-pathname :direction :output :if-exists :supersede :if-does-not-exist :create)
	(write-line first-line out)
	(loop for (nil line) across records
	    do (write-line line out)))))
  (values))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Attack plan recognizer support routines.
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This can generalized to deal with addresses of typical representatives
;;; of an ensemble of computers.
(defun ip-matches-ip-address-string (ip ip-address-string)
  (let ((other-ip (parse-ip-address ip-address-string)))
    (eql (ip-address-integer ip)
	 (ip-address-integer other-ip))))


(defun computer-with-ip-address (ip-address)
  (ask* `[and [object-type-of ?computer computer]
	      [value-of (?computer ip-addresses) ,ip-address]]
	(return-from computer-with-ip-address ?computer)))

(defun ensemble-of-computer (computer)
  (when (typical-p computer)
    (ensemble computer)))

(defclass hypothesis ()
  ((matches :initarg :matches :initform nil :accessor matches)
   (head :initarg :head :initform nil :accessor head)
   (remaining :initarg :remaining :initform nil :accessor remaining))
  )

(defmethod computer-matches-ip ((computer computer) (ip-string string))
  (loop for computer-ip in (ip-addresses computer)
      thereis (string-equal (ip-address-string computer-ip) ip-string)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The driver
;;; Maps over all records in the file
;;; For each record
;;; For each active hypothesis checks if it matches the record
;;; If so this creates a new hypothesis that's advanced by one record
;;; If this hypothesis has no remaining actions, you've found an attack
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defgeneric match-action (action-type action record-fields &optional stream))

(defun matcher (plans pathname &key (verbose t) rate)
  (let ((active (loop for plan in plans
		    collect (make-instance 'hypothesis :head (first plan) :remaining (rest plan))))
	(full-matches nil)
	(processed 0))
    (with-mapped-records (pathname *all-keys* :key-location :in-file :vector vector)
      ;; (format t "~%Number of active hypotheses: ~a" (length active))
      (incf processed)
      (when (and rate (zerop (mod processed rate)))
	(format t "~%Processed ~d records" processed))
      (loop for hypothesis in active
	  for action = (head hypothesis)
	  for action-type = (action-name action)
	  for match = (match-action action-type action vector)
	  when match
	  collect (make-instance 'hypothesis
		    :matches (append (matches hypothesis) (list (list action (copy-seq vector))))
		    :head (first (remaining hypothesis))
		    :remaining (rest (remaining hypothesis)))
	  into new-hypotheses
	  and do (when verbose
		   (format t "~%Matched ~a ~a ~% to ~a" (action-name action) (arguments action) vector))
	  finally (loop for new in new-hypotheses
		      if (head new)
		      do (push new active)
		      else
		      do (push new full-matches))))
    (values full-matches active)))

;;; This attempts to match an action to a record from a trace file.
;;; The method is called with the action, the raw record and the alist of fields
;;; in the record.  Which fields are passed is determined by the driver routine.

(defmethod match-action (type (action action) vector &optional (stream *standard-output*))
  (declare (ignore vector ))
  (format stream "~%I don't yet know how to match ~a actions to the data" type)
  )

;;; *all-keys* = "srcip" "sport" "dstip" "dsport" "dur" "service" "Stime" "Ltime" "is_ftp_login" "attack_cat" "Label" "attack_subcat"
;;; but with-fields "lispifies" these strings replacing any non-alphanumerics with hyphens

(defmethod match-action ((type (eql 'connect-via)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "dstip" "service" "attack_cat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (source-computer foothold-role destination-computer protocol) (arguments action)
      (declare (ignore foothold-role))
      (when (and service (string-equal attack-cat ""))
	(and (computer-matches-ip source-computer srcip)
	     (computer-matches-ip destination-computer dstip)
	     ;; service in the trace file is a string
	     (string-equal (string protocol) service)
	     )))))

(defmethod match-action ((type (eql 'guess-password)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("dstip" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (attacker user victim-computer) (arguments action)
      (declare (ignore attacker user))
      (when attack-subcat
	(and (string-equal attack-cat "exploits")
	     (string-equal attack-subcat "password guess")
	     (computer-matches-ip victim-computer dstip))))))

(defmethod match-action ((type (eql 'login)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("attack_cat" "attack_subcat" "dstip") :vector vector :all-fields *all-keys*)
    (destructuring-bind (victim-user victim-os-instance current-foothold-computer current-foothold-role) (arguments action)
      (declare (ignore current-foothold-computer current-foothold-role))
      (when (and attack-cat attack-subcat)
	(and (computer-matches-ip (computer victim-os-instance) dstip)
	     (string-equal attack-cat "login")
	     (string-equal attack-subcat (string (name victim-user)))
	  )))))

(defmethod match-action ((type (eql 'download-software)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "dstip" "service" "attack_cat" "attack_subcat" "label") :vector vector :all-fields *all-keys*)
    ;; [download-software
    (destructuring-bind (package source-computer destination-computer role) (arguments action)
      (declare (ignore package role))
      (when (and (string-equal attack-cat "Download")
		 (string-equal attack-subcat "Malware Download")
		 (string-equal label "1"))
	(and (computer-matches-ip source-computer srcip)
	     (computer-matches-ip destination-computer dstip)
	     (string-equal service "FTP"))
	  ))))

(defmethod match-action ((type (eql 'load-software)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "attack_cat" "attack_subcat" "label") :vector vector :all-fields *all-keys*)
    ;; [load-software
    (destructuring-bind (package victim-computer) (arguments action)
      (declare (ignore package))
      (when  (and (string-equal label "1")
		  (string-equal attack-cat "load")
		  (string-equal attack-subcat "Malware load"))
	(computer-matches-ip victim-computer srcip)))))

(defmethod match-action ((type (eql 'fill-disk)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "label" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    ;; [fill-disk
    (destructuring-bind (attacker victim-computer token) (arguments action)
      (declare (ignore attacker token))
      (when (and (string-equal label "1")
		 (string-equal attack-cat "bricking")
		 (string-equal attack-subcat "Disk Filled"))
	(computer-matches-ip victim-computer srcip)))))

(defmethod match-action ((type (eql 'capture-password-through-keylogger)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "label" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    ;; [capture-password-through-keylogger
    (destructuring-bind (attacker victim-user victim-computer) (arguments action)
      (declare (ignore attacker victim-user ))
      (when (and (string-equal label "1")
		 (string-equal attack-cat "keylogger"))
	(computer-matches-ip victim-computer srcip)))))

(defmethod match-action ((type (eql 'use-access-right-to-modify)) (action action) vector &optional (stream *standard-output*))
  (declare (ignore stream))
  (with-fields (("srcip" "dstip" "service" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    ;; [use-access-right-to-modify
    (destructuring-bind (attacker write whose-right foothold-computer victim-object victim-computer) (arguments action)
      (declare (ignore attacker write whose-right victim-object))
      (when (and (string-equal attack-cat "Database-Access")
		 (string-equal attack-subcat "write")
		 (string-equal service "database"))
	(and (computer-matches-ip victim-computer dstip)
	     (computer-matches-ip foothold-computer srcip))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Telling the story of a matched attack plan
;;;  We start with a sequence of actions with their associated vector
;;;   describing the matched event.
;;;  For each action vector pair we create a description including the times
;;;  If the action is the last thing in its parent plan
;;;  The we described the goal that plans achieves
;;;  If the goal is the last thing in its parent plan
;;;  Then we describe the goal achieved by that plan, etc.
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defgeneric tell-actions-story (action-name action vector &optional stream))
(defgeneric tell-goals-story (goal-name goal &optional stream))

(defun tell-the-story (hypothesis &key pathname (stream *standard-output*))
  (flet ((do-it (stream)
	 (loop for (action vector) in (matches hypothesis)
	     for action-name = (action-name action)
	     for parent = (parent action)
	     for last-step = (first (last (steps parent)))
	     do (tell-actions-story action-name action vector stream)
	     when (eql action last-step)
	     do (clim:indenting-output (stream 4)
		  (tell-plans-story parent stream))))
	 (make-pathname-with-type (file-name type)
	   (merge-pathnames (make-pathname :type type) file-name)))
    (if pathname
	(with-output-to-pdf-stream (pathname stream)
	    (do-it stream))
      (do-it stream)))
  (values))

(defmethod tell-plans-story ((plan plan) stream)
  (let* ((goal (parent plan))
	 (goal-name (goal-name goal)))
    (tell-goals-story goal-name goal stream)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Actions
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; default method
(defmethod tell-actions-story (action-name (action action) (vector array) &optional (stream *standard-output*))
  (format stream "~2%I don't know how to tell the story for ~a type action ~a" action-name action)
  )

(defmethod tell-actions-story ((type (eql 'connect-via)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "srcip" "dstip" "service" "attack_cat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (source-computer foothold-role destination-computer protocol) (arguments action)
      (declare (ignore foothold-role protocol))
      (format stream "~2%At time ~a ~% The computer ~a at ~a connected via ~a ~% to the computer ~a at ~a"
	      (formatted-unix-time stime) (role-name source-computer) srcip service (role-name destination-computer) dstip))))

(defmethod tell-actions-story ((type (eql 'guess-password)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "ltime" "srcip") :vector vector :all-fields *all-keys*)
    (destructuring-bind (attacker user victim-computer) (arguments action)
      (declare (ignore attacker))
      (format stream "~2%Between ~a and ~a~% There was an attempt to guess the password of ~a~% on the computer ~a at ~a"
	      (formatted-unix-time stime) (formatted-unix-time ltime)
	      (name user) (role-name victim-computer) srcip))))

(defmethod tell-actions-story ((type (eql 'login)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("srcip" "stime") :vector vector :all-fields *all-keys*)
    (destructuring-bind (victim-user victim-os-instance current-foothold-computer current-foothold-role) (arguments action)
      (declare (ignore current-foothold-computer current-foothold-role))
      (format stream "~2%At ~a~% There was a login as ~a on our computer ~a at ~a"
	      (formatted-unix-time stime) (name victim-user) (role-name (computer victim-os-instance)) srcip))))

(defmethod tell-actions-story ((type (eql 'download-software)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("srcip" "dstip" "service" "stime" "ltime") :vector vector :all-fields *all-keys*)
    (destructuring-bind (package source-computer destination-computer role) (arguments action)
      (declare (ignore role source-computer))
      (format stream "~2%Between ~a and ~a~% The computer ~a at ~a dowloaded software package ~a ~% using ~a from ~a"
	      (formatted-unix-time stime) (formatted-unix-time ltime)
	      (role-name destination-computer) dstip package
	      service srcip
	  ))))

(defmethod tell-actions-story ((type (eql 'load-software)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "srcip" "attack_cat" "attack_subcat" "label") :vector vector :all-fields *all-keys*)
   (destructuring-bind (package victim-computer) (arguments action)
     (format stream "~2%At ~a~% The computer ~a at ~a ~% loaded previously downloaded software ~a"
	     (formatted-unix-time stime)
	     (role-name victim-computer) srcip package)
     )))

(defmethod tell-actions-story ((type (eql 'fill-disk)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "ltime" "srcip" "label" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (attacker victim-computer token) (arguments action)
      (declare (ignore attacker token))
      (format stream "~2%Between ~a and ~a~% The computer ~a at ~a ~% used the kill disk malware to fill up its disk"
	      (formatted-unix-time stime) (formatted-unix-time ltime)
	      (role-name victim-computer) srcip)
      )))

(defmethod tell-actions-story ((type (eql 'capture-password-through-keylogger)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "srcip" "label" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (attacker victim-user victim-computer) (arguments action)
      (declare (ignore attacker))
      (format stream "~2%At time ~a~% The attacker logged into ~a at ~a as ~a~% This was captured and exfiltrated by a keyloger"
	      (formatted-unix-time stime)
	      (role-name victim-computer) srcip (name victim-user))
      )))

(defmethod tell-actions-story ((type (eql 'use-access-right-to-modify)) (action action) vector &optional (stream *standard-output*))
  (with-fields (("stime" "srcip" "dstip" "service" "attack_cat" "attack_subcat") :vector vector :all-fields *all-keys*)
    (destructuring-bind (attacker write whose-right foothold-computer victim-object victim-computer) (arguments action)
      (declare (ignore foothold-computer))
      (terpri stream)
      (format stream "~2%At ~a~% ~a used the ~a privilege of ~a~% to overwrite the data of ~a ~% on the computer ~a at ~a"
	      (formatted-unix-time stime)
	      (role-name attacker) write (name whose-right)
	      (role-name victim-object)
	      (Role-name victim-computer) srcip)
      )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Goals
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defmethod tell-goals-story :around (goal-name goal &optional (stream *standard-output*))
  (clim:indenting-output (stream 4)
    (call-next-method goal-name goal stream)))

(defmethod tell-goals-story (goal-name (goal goal) &optional (stream *standard-output*))
  (format stream "~2%-->I don't know how to tell the story for ~a type goal ~a" goal-name goal)
  )

(defmethod tell-goals-story ((goal-name (eql 'get-foothold)) (goal goal) &optional (stream *standard-output*))
  ;;; [get-foothold
  (destructuring-bind (victim-computer connection-type) (arguments goal)
      (declare (ignore connection-type))
      (format stream "~2%-->This allowed the attacker to get a foothold on ~a"
	      (role-name victim-computer))))

(defmethod tell-goals-story ((goal-name (eql 'achieve-knowledge-of-password)) (goal goal) &optional (stream *standard-output*))
  ;;; [ACHIEVE-KNOWLEDGE-OF-PASSWORD
  (destructuring-bind (attacker victim-user victim-computer) (arguments goal)
    (format stream "~2%-->This allowed ~a to get the credentials of ~a on ~a"
	    (role-name attacker) (name victim-user)
	    (role-name victim-computer))))

(defmethod tell-goals-story ((goal-name (eql 'achieve-remote-shell)) (goal goal) &optional (stream *standard-output*))
  ;;; [ACHIEVE-REMOTE-SHELL
  (destructuring-bind (victim-os-instance victim-user) (arguments goal)
    (let ((victim-computer (computer victim-os-instance)))
      (format stream "~2%-->This allowed the attacker to get a remote shell on ~a as ~a"
	      (role-name victim-computer) (name victim-user)))))

(defmethod tell-goals-story ((goal-name (eql 'install-malware)) (goal goal) &optional (stream *standard-output*))
  ;;; [install-malware
  (destructuring-bind (attacker victim-computer malware) (arguments goal)
    (format stream "~2%-->This allowed ~a to install the ~a malware on ~a"
	    (role-name attacker) malware (role-name victim-computer))))

(defmethod tell-goals-story ((goal-name (eql 'brick-computer)) (goal goal) &optional (stream *standard-output*))
  ;;; [brick-computer
  (destructuring-bind (attacker victim-computer) (arguments goal)
    (format stream "~2%-->This allowed ~a to brick ~a, causing the user to call a sysadmin"
	    (role-name attacker) (role-name victim-computer))))

(defmethod tell-goals-story ((goal-name (eql 'make-connection)) (goal goal) &optional (stream *standard-output*))
  (fresh-line stream)
  (values))

(defmethod tell-goals-story ((goal-name (eql 'modify)) (goal goal) &optional (stream *standard-output*))
  ;;; [modify
  (destructuring-bind (property object) (arguments goal)
    (format stream "~2%-->This allowed the attacker to corrupt the ~a of ~a"
	    property (role-name object))))
