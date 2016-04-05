;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

(define-predicate-method (ask-data connected) (truth-value continuation)
  (unless (eql truth-value *true*)
    (error 'ji:model-can-only-handle-positive-queries
	    :query self
	    :model (type-of self)))  
  (with-statement-destructured (thing1 thing2 path) self
    (let ((connections (find-paths-between thing1 thing2)))
      (loop for thing in connections
            do (with-unification
                 (unify thing path)
                 (stack-let ((backward-support (list self *true* '(ask-data conneted))))
                   (funcall continuation backward-support)))))))


(defmethod find-paths-between (thing1 thing2)
  (declare (ignore thing1 thing2))
  nil)


(defmethod find-paths-between ((thing1 computer) (thing2 router))
  (cond
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (labels ((do-one-hop (next-subnet path-so-far source)
                   (cond ((member thing2 (routers next-subnet))
                          (when (typep thing2 'switched-subnet)
                            (push (switch thing2) path-so-far))
                          (pushnew (reverse path-so-far) answers :test #'equal))
                         (t (loop for router in (routers next-subnet)
                                  unless (equal router source)
                                  do (loop for subnet in (subnets router)
                                           for my-path = path-so-far
                                           when (typep subnet 'switched-subnet)
                                           do (push (switch subnet) my-path)
                                           do (do-one-hop subnet (cons router my-path) router)))))))
          (loop for subnet in (subnets thing1)
                for starting-path = (if (typep subnet 'switched-subnet) (list (switch subnet)) nil)
                do (do-one-hop subnet starting-path thing1)))
        answers))))

(defmethod find-paths-between ((thing1 computer) (thing2 computer))
  (cond 
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (loop for subnet1 in (subnets thing1)
              do (loop for subnet2 in (subnets thing2)
                       for paths = (find-paths-between subnet1 subnet2)
                       do (loop for path in paths
                                do (pushnew path answers :test #'equal))))
        answers))))

;;; fix to include the switch on the path
(defmethod find-paths-between ((thing1 subnet) (thing2 subnet))
  (cond 
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (labels ((do-one-hop (next-router path-so-far source-subnet)
                   (cond ((member thing2 (subnets next-router))
                          (push next-router path-so-far)
                          (when (typep thing2 'switched-subnet)
                            (push (switch thing2) path-so-far))
                          (pushnew (reverse path-so-far) answers :test #'equal))
                         (t (loop for subnet in (subnets next-router)
                                  for my-path = path-so-far
                                  unless (equal subnet source-subnet)
                                  when (typep subnet 'switch-subnet)
                                  do (push (switch subnet) my-path)
                                  do (loop for router in (routers subnet)
                                           unless (member router path-so-far)
                                           do (do-one-hop router (cons next-router my-path) subnet)))))))
          (loop for router in (routers thing1)
                for starting-path = (if (typep thing1 'switched-subnet) (list (switch thing1)) nil)
                do (do-one-hop router starting-path thing1)))
        answers))))

(defun find-connected (subnet1 subnet2)
  (let ((sub1 (follow-path `(,subnet1)))
        (sub2 (follow-path `(,subnet2))))
    (ask `[connected ,sub1 ,sub2 ?path] 
         #'(lambda (ignore)
             (declare (ignore ignore))
             (format t "~&Subnet ~a is connect to subnet ~a by ~a"
                     sub1 sub2 ?path)))))



(defun find-reachables (computer1 computer2)
  (ask `[reachable-from ,computer1 ,computer2 ?path]
       #'(lambda (ignore)
           (declare (ignore ignore))
           (format t "~%computer ~a is connected to computer ~a by path ~a"
                   computer1 computer2 ?path))))


 

(defun parse-ip-address (ip-address-string)
  (loop for last-position = 0 then (1+ position)
        for position = (position #\. ip-address-string :start last-position)
        collect (read-from-string ip-address-string nil nil :start last-position :end position)
        until (null position))) 

(defun create-ip-address (ip-address-string)
  (let* ((octets (parse-ip-address ip-address-string))
         (name (intern (apply #'format nil "IP-~d.~d.~d.~d" octets)))
         (ip-address (make-object 'ip-address :name name)))
    (loop for octet in '(octet1 octet2 octet3 octet4)
          for value in octets
          do (tell `[value-of (,ip-address ,octet) ,value]))
    ip-address))

(defun add-ip-address-to-computer (ip-address-string computer)
  (let* ((ip-address (create-ip-address ip-address-string)))
    (tell `[value-of (,computer ip-addresses) ,ip-address])))



(defun fill-in-subnet-mask (subnet-mask ip-address-string subnet-mask-string)
  (let ((address-octets (parse-ip-address ip-address-string))
        (mask-octets (parse-ip-address  subnet-mask-string)))
    (loop for octet-name in '(octet1 octet2 octet3 octet4)
          for address-octet in address-octets
          for mask-octet in mask-octets
          do (tell `[value-of (,subnet-mask ip-address ,octet-name) ,address-octet])
             (tell `[value-of (,subnet-mask mask ,octet-name) ,mask-octet]))))

(defun ip-address-is-on-subnet (ip-address subnet)
  (let* ((subnet-mask (ip-address-integer (follow-path `(,subnet mask mask))))
         (subnet-ip-address (ip-address-integer (follow-path `(,subnet mask ip-address))))
         (real-ip-address (ip-address-integer ip-address)))
    (let ((masked-address (logand real-ip-address subnet-mask)))
      (equal masked-address subnet-ip-address))))

(defmethod subnet-is-at-site ((subnet subnet) (site site))
  (let ((sub-ip-address (ip-address-integer (follow-path `(,subnet mask ip-address))))
        (sub-mask (ip-address-integer (follow-path `(,subnet mask mask))))
        (site-ip-address (ip-address-integer (follow-path `(,site net-mask ip-address))))
        (site-mask (ip-address-integer (follow-path `(,site net-mask mask)))))
    (and (= (logand site-mask sub-mask) site-mask)
         (= (logand site-mask sub-ip-address) site-ip-address)))) 




(defun make-positive-location-mask (address-string mask-string)
  (make-location-mask 'positive-location address-string mask-string))

(defun make-negative-location-mask (address-string mask-string)
  (make-location-mask 'negative-location address-string mask-string))

(defun make-location-mask (mask-type address-string mask-string)
  (with-atomic-action
    (let ((the-mask (make-object mask-type :name (gentemp (string-upcase "mask")) :superpart-object nil)))
      (fill-in-subnet-mask the-mask address-string mask-string)
      the-mask)))

;; a subnet mask can be used as a positive location
(defmethod location-is-in-net-segment ((segment subnet-mask) (location subnet-mask))
  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
        (location-mask (ip-address-integer (follow-path `(,location mask))))
        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
    (and 
    ;; location mask must be more specific extension
     (eql (logand segment-mask location-mask) segment-mask)
     ;; location address is on segment
     (equal (logand location-ip-address segment-mask) segment-ip-address))))

(defmethod location-is-in-net-segment ((segment subnet-mask) (location positive-location))
  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
        (location-mask (ip-address-integer (follow-path `(,location mask))))
        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
    (and 
    ;; location mask must be more specific extension
     (eql (logand segment-mask location-mask) segment-mask)
     ;; location address is on segment
     (equal (logand location-ip-address segment-mask) segment-ip-address))))

(defmethod location-is-in-net-segment ((segment subnet-mask) (location negative-location))
  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
        (location-mask (ip-address-integer (follow-path `(,location mask))))
        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
    (not
     (and 
      ;; segment mask must be more specific extension
      (eql (logand segment-mask location-mask) location-mask)
      ;; segment address is in the location span
      (equal (logand segment-ip-address location-mask) location-ip-address)))))

(defmethod location-is-in-net-segment ((segment subnet-mask) (location ip-address))
  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
        (location-ip-address (ip-address-integer location)))
     ;; location address is on segment
     (equal (logand location-ip-address segment-mask) segment-ip-address)))

(defmethod location-is-in-net-segment ((site site) location)
  (let ((site-mask (follow-path `(,site net-mask))))
    (location-is-in-net-segment site-mask location)))

(defmethod acceptable-location-for-policy ((site site) (location subnet-mask) (policy (eql 'local-only)))
  (location-is-in-net-segment site location))

(defmethod acceptable-location-for-policy ((site site) location (policy (eql 'global)))
  (declare (ignore location))
  t) 


(defmethod path-is-acceptable-for-connection-type (path location connection-type)
  (loop for bridge in path
        always (acceptable-location-for-connection bridge location connection-type)))

(defmethod acceptable-location-for-connection ((bridge computer) location connection-type)
  (ask `[policy-for ,bridge ,connection-type ?bridge-mask]
       #'(lambda (just)
           (declare (ignore just))
           (when (location-is-in-net-segment ?bridge-mask location)
             (return-from acceptable-location-for-connection 
               (values t)))))
  nil)